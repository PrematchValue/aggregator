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

from verified_nodes import load_verified_nodes, merge_candidates, snapshot_content

import executable
import pipeline
import push
import utils
import workflow
import yaml
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
    pages: int = sys.maxsize,
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

        if username and gist_id and access_token:
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

        return [links[i] for i in range(len(links)) if results[i][0] and not results[i][1]]

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
    if tasks and kwargs.get("refresh", False):
        logger.info("skip registering new accounts, will use existing subscriptions for refreshing")
        return tasks

    records: dict[str, AirportRecord] = {}
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
        )

        if crawled:
            for domain, incoming in crawled.items():
                current = records.get(domain)
                if current is None:
                    records[domain] = incoming
                else:
                    current.coupon = incoming.coupon
                    current.api_prefix = incoming.api_prefix
            overwrite = True

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
    )

    if not tasks:
        logger.warning("本轮没有新的机场或有效订阅，将尝试复检历史有效节点")

    # 已有订阅已经做过过期检查，无需再测
    old_subscriptions = set()
    for task in tasks:
        old_subscriptions.update(task.nodes.subscribe_list())

    logger.info(f"start generate subscribes information, tasks: {len(tasks)}")
    generate_conf = os.path.join(PATH, "subconverter", "generate.ini")
    if os.path.exists(generate_conf) and os.path.isfile(generate_conf):
        os.remove(generate_conf)

    results = pipeline.execute_tasks(tasks) if tasks else []
    proxies = list(itertools.chain.from_iterable([x[1] for x in results if x]))
    fresh_count = len(proxies)
    if getattr(args, "geo_rename", False):
        try:
            previous = load_verified_nodes(gist_id, access_token)
        except Exception as exc:
            logger.error("读取历史节点快照失败，为避免覆盖上一轮有效节点，本轮停止发布：" + type(exc).__name__)
            sys.exit(1)
        proxies, recovered = merge_candidates(proxies, previous)
        logger.info(f"节点复检：新获取={fresh_count}，历史候选={len(previous)}，额外找回={recovered}，合计={len(proxies)}")

    if len(proxies) == 0:
        logger.error("新旧候选均无可检测节点，本轮不更新旧订阅")
        sys.exit(1)

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

        masks = utils.multi_thread_run(
            func=clash.check,
            tasks=params,
            num_threads=args.num,
            show_progress=display,
        )

        # 关闭clash
        try:
            process.terminate()
        except:
            logger.error(f"terminate clash process error")

        nodes = [proxies[i] for i in range(len(proxies)) if masks[i]]
        if len(nodes) <= 0:
            logger.error("所有新旧节点均未通过连通检测，保留 Gist 上一轮结果")
            sys.exit(1)

    # Presentation extension only: reuse upstream's Mihomo location engine.
    # All discovery, liveness, parsing and conversion are upstream code.
    if getattr(args, "geo_rename", False):
        from geo_labels import label_verified_nodes
        nodes, geo_stats = label_verified_nodes(nodes, num_threads=args.num)
        logger.info(f"出口地区整理：检测={geo_stats['checked']}，确认={geo_stats['kept']}，"
                    f"未知剔除={geo_stats['unknown']}；国旗命名与分区排序完成")
        if not nodes:
            logger.error("没有确认出口地区的节点；不更新订阅")
            sys.exit(1)

    # Only an exit-verified snapshot is retained; no stale-node archive.
    history_content = snapshot_content(nodes) if getattr(args, "geo_rename", False) else ""
    subscriptions = set()
    for p in proxies:
        # 移除无用的标记
        p.pop("liveness", True)

        sub = p.pop("sub", "")
        if sub:
            subscriptions.add(sub)

    data = {"proxies": nodes}
    urls = list(subscriptions)
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

    # Conversion and validation are independent for each target. A broken
    # sing-box output must never prevent a valid Clash/Surge/V2Ray publication.
    failed_targets = {}
    for t in targets:
        target_name = t[2]
        filepath = os.path.join(DATA_BASE, t[1])
        try:
            success = subconverter.generate_conf(
                generate_conf, t[0], source, t[1], t[2],
                None if getattr(args, 'geo_rename', False) else True, t[3], t[4]
            )
            if not success:
                raise ValueError("无法生成 SubConverter 参数")
            if not subconverter.convert(binname=subconverter_bin, artifact=t[0]):
                raise ValueError("SubConverter 转换失败")
            shutil.move(os.path.join(PATH, "subconverter", t[1]), filepath)

            if target_name in ("clash", "surge"):
                from profile_layout import apply_profile_layout
                with open(filepath, encoding="utf-8") as rendered:
                    profile = rendered.read()
                updated = apply_profile_layout(profile, target_name)
                # Clash Mi: keep the former SubConverter inline routing output.
                # This avoids 20+ remote rule providers on the first client start.
                if target_name == 'surge':
                    from external_rule_sets import externalize_surge
                    updated = externalize_surge(updated)
                with open(filepath, "w", encoding="utf-8") as rendered:
                    rendered.write(updated)

            if target_name == "singbox":
                from singbox_layout import apply_singbox_layout
                with open(filepath, encoding="utf-8") as source_file:
                    profile = source_file.read()
                updated = apply_singbox_layout(profile)
                from external_rule_sets import externalize_singbox
                updated = externalize_singbox(updated)
                with open(filepath, "w", encoding="utf-8") as output_file:
                    output_file.write(updated)

            if target_name == "surge" and username and gist_id:
                from surge_provider import fix_managed_gist_url
                with open(filepath, encoding="utf-8") as source_file:
                    profile = source_file.read()
                profile = fix_managed_gist_url(profile, username, gist_id)
                with open(filepath, "w", encoding="utf-8") as output_file:
                    output_file.write(profile)

            records[t[1]] = filepath
            logger.info(f"{target_name} 转换与校验成功")
        except Exception as exc:
            failed_targets[target_name] = f"{type(exc).__name__}: {exc}"
            records.pop(t[1], None)
            logger.error(f"{target_name} 处理失败，保留该平台旧订阅：{failed_targets[target_name]}")
            continue

    # Minimal output extension: preserve a pure proxy policy-path alongside
    # upstream's normal Surge profile. No independent conversion engine.
    if 'surge.conf' in records:
        from surge_provider import proxy_lines_only
        try:
            with open(records['surge.conf'], 'r', encoding='utf-8') as surge_source:
                provider_content = proxy_lines_only(surge_source.read())
            provider_path = os.path.join(DATA_BASE, 'surge-proxy.conf')
            with open(provider_path, 'w', encoding='utf-8') as provider_file:
                provider_file.write(provider_content)
            records['surge-proxy.conf'] = provider_path
            logger.info('Surge 外部代理节点列表已生成：surge-proxy.conf')
        except (OSError, ValueError):
            # Keep the last two published Surge artifacts unchanged together.
            records.pop('surge.conf', None)
            failed_targets['surge'] = 'Surge 外部节点列表生成失败'
            logger.warning('Surge 外部代理节点列表生成失败；本轮跳过 Surge 两份文件')

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
        urls = [new_subscriptions[i] for i in range(len(new_subscriptions)) if results[i][0] and not results[i][1]]
        discard = len(tasks) - len(urls)

        # 合并新老订阅
        urls.extend(list(old_subscriptions))

        logger.info(f"filter subscriptions finished, total: {total}, found: {len(urls)}, discard: {discard}")

    utils.write_file(filename=os.path.join(DATA_BASE, subscribes_file), lines=urls)
    domains = [utils.extract_domain(url=x, include_protocal=True) for x in urls]

    # 保存实际可使用的网站列表
    utils.write_file(filename=os.path.join(DATA_BASE, "valid-domains.txt"), lines=list(set(domains)))

    # Only independently validated targets are eligible for Gist updates.
    # One PATCH per platform; Surge complete profile and pure proxy list are
    # published together. Files absent from the PATCH retain their old version.
    from output_publish import publication_groups
    groups = publication_groups(targets, records)
    published_targets = []
    if gist_id and access_token:
        push_client = push.PushToGist(token=access_token)
        shared = {}
        if urls:
            shared[subscribes_file] = {"content": "\n".join(urls), "filename": subscribes_file}
        if history_content:
            shared["verified-nodes.json"] = {"content": history_content, "filename": "verified-nodes.json"}
        for target_name, filenames in groups:
            try:
                files = {}
                for filename in filenames:
                    with open(records[filename], "r", encoding="utf-8") as handle:
                        content = utils.trim(handle.read())
                    if not content:
                        raise ValueError(f"空的输出文件：{filename}")
                    files[filename] = {"content": content, "filename": filename}
                # Publish shared node history once, with the first successful
                # target. If that PATCH fails, retry with the next target.
                files.update(shared)
                item = StorageItem(gist_id=gist_id, filename=filenames[0])
                success = push_client.push_to(
                    content="", item=item, payload={"files": files}, group=target_name
                )
                if not success:
                    raise ValueError("Gist PATCH 失败")
                shared = {}
                published_targets.append(target_name)
                logger.info(f"{target_name} Gist 发布成功")
            except Exception as exc:
                failed_targets[target_name] = f"{type(exc).__name__}: {exc}"
                logger.error(f"{target_name} 发布失败，该平台保留旧版：{failed_targets[target_name]}")
        if not published_targets:
            logger.error("全部平台发布失败，旧订阅未被本轮成功更新")
            sys.exit(1)
    else:
        published_targets = [name for name, _ in groups]

    state = "部分成功" if failed_targets else "全部成功"
    logger.info(f"本轮平台更新：{state}；成功={','.join(published_targets) or '无'}；"
                f"失败={','.join(failed_targets) or '无'}")
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a", encoding="utf-8") as summary:
            summary.write(f"\n### Refresh 平台转换与发布：{state}\n")
            summary.write(f"- 成功平台：{', '.join(published_targets) or '无'}\n")
            summary.write(f"- 失败平台（旧版保留）：{', '.join(failed_targets) or '无'}\n")

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
        default=sys.maxsize,
        help="max page number when crawling telegram",
    )

    parser.add_argument(
        "--geo-rename", action="store_true", default=False,
        help="confirm egress country, add flags and sort nodes",
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

    aggregate(args=parser.parse_args())
