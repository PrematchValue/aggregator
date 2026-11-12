# -*- coding: utf-8 -*-

# @Author  : wzdnzd
# @Time    : 2022-07-15

import argparse
import itertools
import os
import random
import re
import shutil
import subprocess
import sys
import time

import executable
import pipeline
import push
import utils
import workflow
import yaml
import collect_safety as safety
from airport import AirPort
from config.models import NodeInput, SiteConfig, StorageItem
from crawl.helpers import check_status, naming_task
from discovery import AirportRecord, collect_airport, parse_records, save_records
from logger import logger
from urlvalidator import isurl
from workflow import TaskConfig

import clash
import subconverter

PATH = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

DATA_BASE = os.path.join(PATH, "data")


def assign(
    bin_name: str,
    domains_file: str = "",
    overwrite: bool = False,
    pages: int = 50,
    allow_gmail_alias: bool = False,
    display: bool = True,
    num_threads: int = 0,
    **kwargs: object,
) -> list[TaskConfig]:
    def load_exist(username: str, gist_id: str, access_token: str, filename: str) -> list[str]:
        if not filename:
            return []

        subscriptions = set()

        pattern = r"^https?:\/\/[^\s]+"
        local_file = os.path.join(DATA_BASE, filename)
        if os.path.exists(local_file) and os.path.isfile(local_file):
            with open(local_file, "r", encoding="utf8") as f:
                items = re.findall(pattern, str(f.read()), flags=re.M)
                if items:
                    subscriptions.update(items)

        if kwargs.get("existing_subscriptions") is not None:
            subscriptions.update(kwargs["existing_subscriptions"])
        elif username and gist_id and access_token:
            push_tool = push.PushToGist(token=access_token)
            url = push_tool.raw_url(item=StorageItem(username=username, gist_id=gist_id, filename=filename))

            content = utils.http_get(url=url, timeout=30)
            items = re.findall(pattern, content, flags=re.M)
            if items:
                subscriptions.update(items)

        logger.info("start checking whether existing subscriptions have expired")

        # 过滤已过期订阅并返回
        links = list(subscriptions)
        results = utils.multi_thread_run(
            func=check_status,
            tasks=links,
            num_threads=num_threads,
            show_progress=display,
        )

        # A temporary timeout or an incomplete status response is NOT expiry
        # proof. Keep such URLs for retry by pipeline.execute_tasks instead of
        # blocking an entire Collect/Refresh or silently deleting the source.
        # Only explicit expiry (the second status flag) permits deletion.
        responses = list(results or [])
        active, unresolved, expired = [], [], []
        for index, link in enumerate(links):
            result = responses[index] if index < len(responses) else None
            if isinstance(result, (tuple, list)) and len(result) >= 2:
                if result[1]:
                    expired.append(link)
                elif result[0]:
                    active.append(link)
                else:
                    unresolved.append(link)
            else:
                unresolved.append(link)

        # Return details to aggregate without changing assign's return type.
        unresolved_sources = kwargs.get("unresolved_sources")
        if isinstance(unresolved_sources, set):
            unresolved_sources.update(unresolved)
        logger.info(
            f"历史订阅校验：正常={len(active)}，暂不可达={len(unresolved)}，"
            f"明确过期={len(expired)}；暂不可达保留并继续采集"
        )
        return active + unresolved

    subscribes_file = utils.trim(kwargs.get("subscribes_file", ""))
    access_token = utils.trim(kwargs.get("access_token", ""))
    gist_id = utils.trim(kwargs.get("gist_id", ""))
    username = utils.trim(kwargs.get("username", ""))
    skip_captcha = kwargs.get("skip_captcha", False)

    # 加载已有订阅
    subscriptions = load_exist(username, gist_id, access_token, subscribes_file)
    logger.info(f"load exists subscription finished, count: {len(subscriptions)}")

    # 是否允许特殊协议
    special_protocols = AirPort.enable_special_protocols()

    tasks = (
        [
            TaskConfig(
                name=utils.random_chars(length=8),
                nodes=NodeInput(subscribe=x),
                bin_name=bin_name,
                special_protocols=special_protocols,
            )
            for x in subscriptions
            if x
        ]
        if subscriptions
        else []
    )

    # 仅更新已有订阅
    if kwargs.get("refresh", False):
        logger.info("skip registering new accounts, will use existing subscriptions for refreshing")
        return tasks

    max_candidates = max(1, int(kwargs.get("max_candidates", 100)))
    excluded = {utils.extract_domain(x, False).lower() for x in subscriptions}

    records: dict[str, AirportRecord] = {}
    crawled = {}
    delimiter = "@#@#"
    domains_file = utils.trim(domains_file)
    if not domains_file:
        domains_file = "domains.txt"

    # 加载已有站点列表
    fullpath = os.path.join(DATA_BASE, domains_file)
    if os.path.exists(fullpath) and os.path.isfile(fullpath):
        with open(fullpath, "r", encoding="UTF8") as handle:
            records.update(parse_records(content=str(handle.read()), delimiter=delimiter))

    # 爬取新站点列表
    if not records or overwrite:
        crawled = collect_airport(
            channel="jichang_list",
            page_num=pages,
            num_threads=num_threads,
            allow_gmail_alias=allow_gmail_alias,
            display=display,
            filepath=os.path.join(DATA_BASE, "coupons.txt"),
            delimiter=delimiter,
            skip_captcha=skip_captcha,
            max_candidates=max_candidates,
            exclude_hosts=tuple(excluded),
            incremental_state=kwargs.get("incremental_state"),
            checkpoint=kwargs.get("checkpoint"),
        )

        if crawled:
            # Overwrite means replace the stale catalogue, not append its entire history.
            records = dict(crawled)
            overwrite = True

    # A failed discovery must not fall back to probing the entire stale catalogue.
    if overwrite and not crawled:
        records = {}

    # 加载自定义机场列表
    customize_link = utils.trim(kwargs.get("customize_link", ""))
    if customize_link:
        if isurl(customize_link):
            records.update(parse_records(content=utils.http_get(url=customize_link), delimiter=delimiter))
        else:
            local_file = os.path.join(DATA_BASE, customize_link)
            if local_file != fullpath and os.path.exists(local_file) and os.path.isfile(local_file):
                with open(local_file, "r", encoding="UTF8") as handle:
                    records.update(parse_records(content=str(handle.read()), delimiter=delimiter))

    if not records:
        logger.error("cannot collect any new airport for free use")
        return tasks

    records = select_candidates(records, excluded, max_candidates)
    if overwrite:
        save_records(records=records, filepath=fullpath, delimiter=delimiter, full=True)

    sites = []
    for domain, record in records.items():
        name = naming_task(url=domain)
        sites.append(
            SiteConfig(
                name=name,
                domain=domain,
                coupon=record.coupon,
                invite_code=record.invite_code,
                api_prefix=record.api_prefix or "/api/v1/",
                skip_captcha=skip_captcha,
            )
        )

    assigned, _ = pipeline.assign_sites(
        sites=sites,
        groups={},
        retry=3,
        bin_name=bin_name,
        allow_gmail_alias=allow_gmail_alias,
    )
    tasks.extend(assigned)
    return tasks


def select_candidates(records, excluded, limit):
    selected, seen = {}, set(excluded)
    for domain, record in records.items():
        host = utils.extract_domain(domain, False).lower()
        if not host or host in seen or not isurl(domain):
            continue
        seen.add(host)
        selected[domain] = record
        if len(selected) >= limit:
            break
    logger.info(f"candidate budget: selected={len(selected)}, skipped={len(records) - len(selected)}")
    return selected


def aggregate(args: argparse.Namespace) -> None:
    def parse_gist_link(link: str) -> tuple[str, str]:
        # 提取 gist 用户名及 id
        words = utils.trim(link).split("/", maxsplit=1)
        if len(words) != 2:
            logger.error(f"cannot extract username and gist id due to invalid github gist link")
            return "", ""

        return utils.trim(words[0]), utils.trim(words[1])

    clash_bin, subconverter_bin = executable.which_bin()
    display = not args.invisible

    subscribes_file = "subscribes.txt"
    access_token = utils.trim(args.key)
    username, gist_id = parse_gist_link(args.gist)

    revision, previous = "", {}
    if gist_id and access_token:
        revision, previous = safety.read_gist(gist_id, access_token)

    checkpoint = None
    if getattr(args, "incremental", False):
        if not gist_id or not access_token:
            raise safety.PublicationError("incremental mode requires Gist credentials for durable checkpoints")
        from scan_state import GistCheckpoint
        # Fail early on corrupt historical artifacts rather than discovering
        # problems only after lengthy collection and conversion.
        known_formats = {"clash.yaml": "clash", "v2ray.txt": "v2ray",
                         "singbox.json": "singbox", "surge.conf": "surge",
                         "surge-proxy.conf": "surge"}
        baseline_counts = {}
        for filename, target in known_formats.items():
            if previous.get(filename):
                baseline_counts[target] = safety.artifact_count(previous[filename], target)
        logger.info(f"订阅发布预检通过：旧文件={len(baseline_counts)}，"
                    f"历史 Clash 节点={baseline_counts.get('clash', 0)}")
        checkpoint = GistCheckpoint(gist_id, access_token, previous)
        # Verify Gist PATCH permission BEFORE any costly hour-long scan.
        checkpoint.save()
        logger.info("Gist 断点写入预检通过；正式订阅未修改")
        logger.info(f"持久化扫描状态：已有机场记录={len(checkpoint.state.sites)}，"
                    f"节点检测记录={len(checkpoint.state.nodes)}；仅保存哈希与状态")

    unresolved_sources: set[str] = set()
    tasks = assign(
        bin_name=subconverter_bin,
        domains_file="domains.txt",
        overwrite=args.overwrite,
        pages=args.pages,
        allow_gmail_alias=args.easygoing,
        display=display,
        num_threads=args.num,
        refresh=args.refresh,
        skip_captcha=args.skip_captcha,
        username=username,
        gist_id=gist_id,
        access_token=access_token,
        subscribes_file=subscribes_file,
        customize_link=args.custom_sites,
        max_candidates=args.max_candidates,
        existing_subscriptions=safety.subscription_urls(previous.get(subscribes_file, "")) if revision else None,
        unresolved_sources=unresolved_sources,
        incremental_state=checkpoint.state if checkpoint is not None and not args.refresh else None,
        checkpoint=checkpoint if not args.refresh else None,
    )

    if not tasks and not getattr(args, "public_sources", False):
        logger.error("cannot found any valid config, exit")
        sys.exit(1)

    # 已有订阅已经做过过期检查，无需再测
    old_subscriptions = set()
    for task in tasks:
        old_subscriptions.update(task.nodes.subscribe_list())

    logger.info(f"start generate subscribes information, tasks: {len(tasks)}")
    generate_conf = os.path.join(PATH, "subconverter", "generate.ini")
    if os.path.exists(generate_conf) and os.path.isfile(generate_conf):
        os.remove(generate_conf)

    results = pipeline.execute_tasks(tasks)
    proxies = list(itertools.chain.from_iterable([x[1] for x in results if x]))
    # Reviewable public Clash feeds complement airport registration and are
    # reloaded on BOTH Collect and Refresh. Never persist them as private
    # subscription URLs, or let a temporary public-feed outage expire a source.
    if getattr(args, 'public_sources', False):
        from public_sources import gather_public_nodes
        public_nodes, public_counts = gather_public_nodes(logger=logger)
        logger.info(f"公开节点：新增候选={len(public_nodes)}，成功读取源={sum(n > 0 for n in public_counts.values())}")
        proxies.extend(public_nodes)
    # Last published, flag-confirmed nodes remain available as *candidates*
    # for new real HTTP and egress checks even if a source times out today.
    # They receive NO automatic pass and are not written back unless verified.
    if getattr(args, "geo_rename", False):
        from node_history import previous_confirmed_candidates
        historical = previous_confirmed_candidates(previous.get("clash.yaml", ""))
        if historical:
            proxies.extend(historical)
            logger.info(f"历史节点：加入复测候选={len(historical)}；不会免检发布")
    proxies = safety.valid_nodes(proxies)

    if len(proxies) == 0:
        logger.error("exit because cannot fetch any proxy node")
        sys.exit(1)

    # Deduplication can merge identical nodes from several healthy subscriptions.
    fetched_subscriptions = {p["sub"] for p in proxies if p.get("sub")}

    nodes, workspace = [], os.path.join(PATH, "clash")

    if args.skip:
        nodes = clash.filter_proxies(proxies).get("proxies", [])
    else:
        binpath = os.path.join(workspace, clash_bin)
        confif_file = "config.yaml"
        proxies = clash.generate_config(workspace, list(proxies), confif_file)

        # 可执行权限
        utils.chmod(binpath)

        logger.info(f"startup clash now, workspace: {workspace}, config: {confif_file}")
        process = subprocess.Popen(
            [
                binpath,
                "-d",
                workspace,
                "-f",
                os.path.join(workspace, confif_file),
            ]
        )
        logger.info(f"clash start success, begin check proxies, num: {len(proxies)}")

        time.sleep(random.randint(3, 6))
        params = [
            [p, clash.EXTERNAL_CONTROLLER, 5000, args.url, args.delay, False] for p in proxies if isinstance(p, dict)
        ]

        try:
            if process.poll() is not None:
                raise safety.PublicationError("proxy checker failed to start; keeping previous publication")
            masks = utils.multi_thread_run(
                func=clash.check,
                tasks=params,
                num_threads=args.num,
                show_progress=display,
            )
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

        nodes = [proxies[i] for i in range(len(proxies)) if masks[i]]
        if len(nodes) <= 0:
            logger.error(f"cannot fetch any proxy")
            sys.exit(1)

    if args.probe_sample:
        sample = random.sample(nodes, min(len(nodes), args.probe_sample))
        checks = utils.multi_thread_run(safety.tcp_probe, sample, num_threads=min(args.num, 16))
        logger.info(f"advisory TCP sample: checked={len(checks)}, reachable={checks.count('reachable')}, "
                    f"unknown={checks.count('unknown')}, skipped={checks.count('skipped')}; no nodes removed")

    # Label only after final node selection: never change collection or liveness decisions.
    if getattr(args, "geo_rename", False):
        from node_labels import relabel_and_sort

        original_types = [p.get('type', 'unknown') for p in nodes if isinstance(p, dict)]
        nodes, geo_stats = relabel_and_sort(
            nodes,
            previous_clash=previous.get("clash.yaml", ""),
            num_threads=min(max(1, args.num), 24),
            chunk_size=55,
            retry_unknown=True,
        )
        logger.info(
            f"地区整理：总数={geo_stats['total']}，出口新确认={geo_stats['fresh']}，"
            f"沿用历史地区={geo_stats['historical']}，未知={geo_stats['unknown']}；筛除未知地区"
        )
        logger.info(f"真实代理连通性：验证通过={geo_stats.get('live', 0)}，"
                    f"未确认或未完成={geo_stats.get('not_live', 0)}，"
                    f"二轮补回地区={geo_stats.get('recovered', 0)}；仅代表GitHub云端")
        logger.info(f"Mihomo批次隔离：尝试={geo_stats.get('batch_attempts', 0)}，"
                    f"拆分={geo_stats.get('isolated_splits', 0)}，"
                    f"始终未能执行节点级检测={geo_stats.get('unprobed', 0)}，"
                    f"已连通但未定位={geo_stats.get('connected_no_geo', 0)}")
        if checkpoint is not None:
            from node_labels import identity, LABEL_RE
            checkpoint.state.mark_nodes(nodes, identity=identity,
                                        verified_label=lambda p: bool(LABEL_RE.fullmatch(str(p.get("name", "")))))
            checkpoint.save()  # Save independently from conversion/publication.
            logger.info(f"节点状态断点已保存：记录={len(checkpoint.state.nodes)}")
        from node_labels import only_confirmed
        nodes, removed_unknown = only_confirmed(nodes)
        logger.info(f"地区筛选：保留={len(nodes)}，剔除未知={removed_unknown}")
        from egress_region import format_protocol_summary
        logger.info("地区筛选按协议：" + format_protocol_summary(
            original_types, [p.get('type', 'unknown') for p in nodes if isinstance(p, dict)]
        ))
        if not nodes:
            if checkpoint is not None:
                logger.warning("本轮无可确认地区的节点；未发布订阅，扫描进度已经保存")
                return
            raise safety.PublicationError("no region-confirmed nodes; keeping previous Gist publication")

    subscriptions = set(fetched_subscriptions) if args.skip else set()
    for p in nodes:
        # 移除无用的标记
        p.pop("liveness", True)

        sub = p.pop("sub", "")
        if sub:
            subscriptions.add(sub)

    # Keep all previous subscriptions that were not explicitly expired,
    # including sources that gave no nodes in this run due to a transient
    # network error. Otherwise they would vanish from subscribes.txt/Gist.
    subscriptions.update(old_subscriptions)
    data = {"proxies": nodes}
    urls = sorted(subscriptions)
    source = "proxies.yaml"

    # 如果文件夹不存在则创建
    os.makedirs(DATA_BASE, exist_ok=True)

    supplier = os.path.join(PATH, "subconverter", source)
    if os.path.exists(supplier) and os.path.isfile(supplier):
        os.remove(supplier)

    with open(supplier, "w+", encoding="utf8") as f:
        yaml.add_representer(clash.QuotedStr, clash.quoted_scalar)
        yaml.dump(data, f, allow_unicode=True)

    if os.path.exists(generate_conf) and os.path.isfile(generate_conf):
        os.remove(generate_conf)

    targets, records = [], {}
    for target in args.targets:
        target = utils.trim(target).lower()
        convert_name = f'convert_{target.replace("&", "_").replace("=", "_")}'

        filename = subconverter.get_filename(target=target)
        list_only = False if target == "v2ray" or target == "mixed" or "ss" in target else not args.all
        targets.append((convert_name, filename, target, list_only, args.ignore_default_filters))

    artifacts = {}
    for t in targets:
        output = os.path.join(PATH, "subconverter", t[1])
        if os.path.isfile(output):
            os.remove(output)
        success = subconverter.generate_conf(generate_conf, t[0], source, t[1], t[2], None if getattr(args, 'geo_rename', False) else True, t[3], t[4])
        if not success:
            raise safety.PublicationError(f"cannot generate conversion config: {t[2]}")

        if not subconverter.convert(binname=subconverter_bin, artifact=t[0]) or not os.path.isfile(output):
            raise safety.PublicationError(f"conversion failed: {t[2]}; keeping previous publication")
        with open(output, encoding="utf-8") as handle:
            content = handle.read()
        if t[2] == "v2ray" and not content.strip():
            # The legacy SubConverter can report success while producing an
            # empty v2rayN artifact for newer protocols (e.g. Hysteria2/TUIC).
            # Fallback only for this one format, and only from the SAME set of
            # country-confirmed nodes used in all other formats.
            from v2ray_fallback import build_subscription

            try:
                content, skipped = build_subscription(nodes)
            except ValueError:
                raise safety.PublicationError(
                    "v2ray converter returned empty and no compatible URI can be built; "
                    "keeping previous Gist publication"
                ) from None
            with open(output, "w", encoding="utf-8") as fallback_file:
                fallback_file.write(content)
            logger.info(
                f"V2ray 转换器输出为空，已使用兼容协议链接兜底："
                f"生成={safety.artifact_count(content, 'v2ray')}，"
                f"不支持协议数={sum(skipped.values())}；不输出凭据"
            )
        safety.artifact_count(content, t[2])
        artifacts[t[1]] = (t[2], content)
        records[t[1]] = output
        if t[2] == "surge":
            # Preserve the full surge.conf for direct import. The policy-path
            # resource must contain only real proxy declarations, not DIRECT,
            # GLOBAL-DIRECT, policy groups or [Rule] entries.
            from surge_provider import proxy_lines_only

            provider_content = proxy_lines_only(content)
            safety.artifact_count(provider_content, "surge")
            provider_name = "surge-proxy.conf"
            provider_path = os.path.join(PATH, "subconverter", provider_name)
            with open(provider_path, "w", encoding="utf-8") as provider_file:
                provider_file.write(provider_content)
            artifacts[provider_name] = ("surge", provider_content)
            records[provider_name] = provider_path

    if len(records) > 0:
        os.remove(supplier)
    else:
        logger.error(f"all targets convert failed, you can view the temporary file: {supplier}")
        sys.exit(1)

    logger.info(f"found {len(nodes)} proxies, save it to {list(records.values())}")

    life, traffic = max(0, args.life), max(0, args.flow)
    if life > 0 or traffic > 0:
        # 过滤出新的订阅并检查剩余流量和过期时间是否满足要求
        new_subscriptions = [x for x in urls if x not in old_subscriptions]

        tasks = [[x, 2, traffic, life, 0, True] for x in new_subscriptions]
        results = utils.multi_thread_run(
            func=check_status,
            tasks=tasks,
            num_threads=args.num,
            show_progress=display,
        )

        total = len(urls)

        # 筛选出为符合要求的订阅
        urls = [link for link, result in zip(new_subscriptions, results) if result and result[0] and not result[1]]
        discard = len(tasks) - len(urls)

        # 合并新老订阅
        urls.extend(old_subscriptions & subscriptions)

        logger.info(f"filter subscriptions finished, total: {total}, found: {len(urls)}, discard: {discard}")

    try:
        safety.check_publication(artifacts, previous, urls, allow_public_only=bool(
            getattr(args, "public_sources", False) and nodes))
    except safety.PublicationError as exc:
        if checkpoint is not None and (str(exc).startswith("node count dropped") or
                                       str(exc).startswith("too many previous sources")):
            logger.warning(f"本轮安全保护：{exc}；保留旧订阅，已保存扫描和节点状态")
            return
        raise
    if unresolved_sources and previous.get("clash.yaml"):
        # An intermittent historical source must never cause a node-count
        # decrease to replace the last known-good publication. Discovery and
        # conversion still run, so new nodes can be published once they offset
        # the missing source. The stronger guard applies only to transient
        # failures; the ordinary 50% threshold remains for all other runs.
        old_count = safety.artifact_count(previous["clash.yaml"], "clash")
        if len(nodes) < old_count:
            if checkpoint is not None:
                logger.warning(f"本轮安全保护：{len(unresolved_sources)} 条历史订阅暂不可达，"
                               f"节点数 {old_count} -> {len(nodes)}；旧订阅不覆盖，扫描进度已保存")
                return
            raise safety.PublicationError(
                f"{len(unresolved_sources)} historical source(s) temporarily unreachable; "
                f"retaining previous Gist because node count would fall "
                f"({old_count} -> {len(nodes)})"
            )

    # 如有必要，上传至 Gist
    if gist_id and access_token:
        item = StorageItem(gist_id=gist_id, filename=list(records.keys())[0])
        files = {name: {"content": content, "filename": name}
                 for name, (_, content) in artifacts.items()}

        if urls:
            files[subscribes_file] = {"content": "\n".join(urls), "filename": subscribes_file}

        if files:
            current_revision, _ = safety.read_gist(gist_id, access_token)
            if checkpoint is not None:
                checkpoint.assert_unchanged_publication()
                # Our own checkpoint PATCH operations update Gist's revision.
                # Compare published files, never reject our own state writes.
            elif current_revision != revision:
                raise safety.PublicationError("gist changed during collection; keeping newer publication")
            push_client = push.PushToGist(token=access_token)

            # 上传
            success = push_client.push_to(content="", item=item, payload={"files": files}, group="collect")
            if success:
                logger.info(f"upload proxies and subscriptions to gist successed")
            else:
                raise safety.PublicationError("upload failed; local subscriptions were not replaced")

    for filename, source_path in records.items():
        shutil.move(source_path, os.path.join(DATA_BASE, filename))
    utils.write_file(filename=os.path.join(DATA_BASE, subscribes_file), lines=sorted(set(urls)))
    domains = [utils.extract_domain(url=x, include_protocal=True) for x in urls]
    utils.write_file(filename=os.path.join(DATA_BASE, "valid-domains.txt"), lines=sorted(set(domains)))

    # 清理工作空间
    workflow.cleanup(workspace, [])


class CustomHelpFormatter(argparse.HelpFormatter):
    def _format_action_invocation(self, action: argparse.Action) -> str:
        if action.choices:
            parts = []
            if action.option_strings:
                parts.extend(action.option_strings)

                # 移除使用帮助信息中 -t 或 --targets 附带的过长的可选项信息
                if action.nargs != 0 and action.option_strings != ["-t", "--targets"]:
                    default = action.dest.upper()
                    args_string = self._format_args(action, default)
                    parts[-1] += " " + args_string
            else:
                args_string = self._format_args(action, action.dest)
                parts.append(args_string)
            return ", ".join(parts)
        else:
            return super()._format_action_invocation(action)


if __name__ == "__main__":
    env_parser = argparse.ArgumentParser(add_help=False)
    env_parser.add_argument(
        "--environment",
        type=str,
        default=".env",
        help="environment file name",
    )
    env_args, _ = env_parser.parse_known_args()
    utils.load_dotenv(env_args.environment)

    parser = argparse.ArgumentParser(formatter_class=CustomHelpFormatter, parents=[env_parser])
    parser.add_argument(
        "-a",
        "--all",
        dest="all",
        action="store_true",
        default=False,
        help="generate full configuration for clash",
    )

    parser.add_argument(
        "-c",
        "--skip-captcha",
        dest="skip_captcha",
        action="store_true",
        default=False,
        help="discard candidate sites that may require human-authentication",
    )

    parser.add_argument(
        "-d",
        "--delay",
        type=int,
        required=False,
        default=5000,
        help="proxies max delay allowed",
    )

    parser.add_argument(
        "-e",
        "--easygoing",
        dest="easygoing",
        action="store_true",
        default=False,
        help="try registering with a gmail alias when you encounter a whitelisted mailbox",
    )

    parser.add_argument(
        "-f",
        "--flow",
        type=int,
        required=False,
        default=0,
        help="remaining traffic available for use, unit: GB",
    )

    parser.add_argument(
        "-g",
        "--gist",
        type=str,
        required=False,
        default=os.environ.get("GIST_LINK", ""),
        help="github username and gist id, separated by '/'",
    )

    parser.add_argument(
        "-i",
        "--invisible",
        dest="invisible",
        action="store_true",
        default=False,
        help="don't show check progress bar",
    )

    parser.add_argument(
        "-k",
        "--key",
        type=str,
        required=False,
        default=os.environ.get("GIST_PAT", ""),
        help="github personal access token for editing gist",
    )

    parser.add_argument(
        "-l",
        "--life",
        type=int,
        required=False,
        default=0,
        help="remaining life time, unit: hours",
    )

    parser.add_argument(
        "-n",
        "--num",
        type=int,
        required=False,
        default=64,
        help="threads num for check proxy",
    )

    parser.add_argument(
        "-o",
        "--overwrite",
        dest="overwrite",
        action="store_true",
        default=False,
        help="overwrite domains",
    )

    parser.add_argument(
        "-p",
        "--pages",
        type=int,
        required=False,
        default=50,
        help="max page number when crawling telegram",
    )

    parser.add_argument(
        "-r",
        "--refresh",
        dest="refresh",
        action="store_true",
        default=False,
        help="refresh and remove expired proxies with existing subscriptions",
    )

    parser.add_argument(
        "-s",
        "--skip",
        dest="skip",
        action=argparse.BooleanOptionalAction,
        default=utils.env_bool("SKIP_ALIVE_CHECK", False),
        help="skip usability checks",
    )

    parser.add_argument(
        "-t",
        "--targets",
        nargs="+",
        choices=subconverter.CONVERT_TARGETS,
        default=["clash", "v2ray", "singbox"],
        help=f"choose one or more generated profile type. default to clash, v2ray and singbox. supported: {subconverter.CONVERT_TARGETS}",
    )

    parser.add_argument(
        "-u",
        "--url",
        type=str,
        required=False,
        default="https://www.google.com/generate_204",
        help="test url",
    )

    parser.add_argument(
        "-v",
        "--ignore-default-filters",
        dest="ignore_default_filters",
        action="store_true",
        default=False,
        help="ignoring default proxies filter rules",
    )

    parser.add_argument(
        "-y",
        "--custom-sites",
        type=str,
        required=False,
        default=os.environ.get("CUSTOMIZE_LINK", ""),
        help="the url to the list of airports that you maintain yourself",
    )

    parser.add_argument(
        '--public-sources', action='store_true', default=False,
        help='collect additional reviewed public YAML feeds on Collect/Refresh',
    )

    parser.add_argument("--incremental", action="store_true",
                        help="persistent full-discovery incremental Collect/Refresh with Gist checkpoints")
    parser.add_argument("--geo-rename", action="store_true", help="identify egress location and sort nodes")
    parser.add_argument("--max-candidates", type=int, default=100, help="maximum new airports per collection")
    parser.add_argument("--probe-sample", type=int, default=0, help="advisory public TCP endpoint sample; never removes nodes")
    args = parser.parse_args()
    if args.max_candidates < 1 or args.probe_sample < 0:
        parser.error("max-candidates must be positive and probe-sample must be nonnegative")
    try:
        aggregate(args=args)
    except safety.PublicationError as exc:
        logger.error(str(exc))
        sys.exit(1)
