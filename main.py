import time
import json
import os
from astrbot.api.event import filter, AstrMessageEvent, MessageEventResult
from astrbot.api.star import Context, Star, register
from astrbot.api import logger

from .query import ServerQuery
from .geocode import reverse_geocode
from .auth import (
    generate_license_key,
    verify_license_key,
    load_auth_config,
    save_auth_config,
    load_license_keys,
    save_license_keys,
    add_license_key,
    mark_key_as_used,
    is_key_used,
    load_authorizations,
    save_authorizations,
    get_authorization,
    set_authorization,
    extend_authorization,
    is_authorized,
    get_expire_time,
    get_all_authorizations,
    delete_authorization,
    cleanup_expired_authorizations,
)

API_BASE_URL = "https://api.scum masters.com" if False else "https://api.scum masters.com"

@register("astrbot_plugin_scum", "SCUM", "SCUM服务器查询与授权管理插件", "1.0.0")
class SCUMPlugin(Star):
    def __init__(self, context: Context, config: dict = None):
        super().__init__(context)
        try:
            from astrbot.core.utils.astrbot_path import get_astrbot_data_path
            config_path = os.path.join(get_astrbot_data_path(), "config", "astrbot_plugin_scum_config.json")
            if os.path.exists(config_path):
                with open(config_path, "r", encoding="utf-8-sig") as f:
                    self.config = json.load(f)
            else:
                self.config = config or {}
        except Exception as e:
            logger.error(f"加载插件配置失败: {e}")
            self.config = config or {}

        self.auth_key = self.config.get("auth_key", "")
        self.default_days = self.config.get("default_days", 30)
        self.server_query = ServerQuery(API_BASE_URL)

    @filter.command("服务器查询")
    async def query_server(self, event: AstrMessageEvent) -> None:
        message = event.message_obj.content.strip()
        if not message.startswith("服务器查询"):
            return

        parts = message.split()
        if len(parts) < 2:
            yield event.plain_result("❌ 请输入服务器ID，格式：服务器查询 <ID>")
            return

        server_id = parts[1].strip()
        result = await self.server_query.query_by_id_simple(server_id)
        yield event.plain_result(result)

    @filter.command("服务器详情")
    async def query_server_detail(self, event: AstrMessageEvent) -> None:
        message = event.message_obj.content.strip()
        if not message.startswith("服务器详情"):
            return

        parts = message.split()
        if len(parts) < 2:
            yield event.plain_result("❌ 请输入服务器ID，格式：服务器详情 <ID>")
            return

        server_id = parts[1].strip()
        result = await self.server_query.query_by_id_detailed(server_id)
        yield event.plain_result(result)

    @filter.command("搜索服务器")
    async def search_server(self, event: AstrMessageEvent) -> None:
        message = event.message_obj.content.strip()
        if not message.startswith("搜索服务器"):
            return

        parts = message.split(maxsplit=1)
        if len(parts) < 2:
            yield event.plain_result("❌ 请输入关键词，格式：搜索服务器 <关键词>")
            return

        keyword = parts[1].strip()
        result = await self.server_query.search_servers(keyword)
        yield event.plain_result(result)

    @filter.command("服务器排名")
    async def server_ranking(self, event: AstrMessageEvent) -> None:
        result = await self.server_query.get_server_ranking()
        yield event.plain_result(result)

    @filter.command("激活卡密")
    async def activate_license(self, event: AstrMessageEvent) -> None:
        message = event.message_obj.content.strip()
        if not message.startswith("激活卡密"):
            return

        parts = message.split()
        if len(parts) < 2:
            yield event.plain_result("❌ 请输入卡密，格式：激活卡密 <卡密>")
            return

        key = parts[1].strip()
        group_id = str(event.message_obj.group_id)

        if not self.auth_key:
            yield event.plain_result("❌ 授权密钥未配置")
            return

        if is_key_used(key):
            yield event.plain_result("❌ 该卡密已被使用过。")
            return

        result = verify_license_key(key, self.auth_key, "")
        if not result["valid"]:
            yield event.plain_result(f"❌ {result['error']}")
            return

        days = result["days"]
        current_auth = get_authorization(group_id)
        current_time = int(time.time())

        if current_auth and current_auth["expire_time"] > current_time:
            new_expire = current_auth["expire_time"] + days * 86400
        else:
            new_expire = current_time + days * 86400

        set_authorization(group_id, new_expire, 0, str(event.message_obj.sender.user_id))
        mark_key_as_used(key, str(event.message_obj.sender.user_id))

        expire_date = time.strftime("%Y-%m-%d %H:%M", time.localtime(new_expire))
        activate_time = time.strftime("%Y-%m-%d %H:%M", time.localtime(current_time))

        yield event.plain_result(f"""✅ 授权已激活/延长！
├─ 激活时间: {activate_time}
├─ 授权群组: {group_id}
├─ 增加天数: {days} 天
└─ 到期时间: {expire_date}

💡 可使用 /授权查询 查看到期时间""")

    @filter.command("授权查询")
    @filter.command("查询授权")
    async def query_auth(self, event: AstrMessageEvent) -> None:
        group_id = str(event.message_obj.group_id)
        auth = get_authorization(group_id)

        if not auth:
            yield event.plain_result("❌ 本群未授权，请先激活卡密。")
            return

        current_time = int(time.time())
        if auth["expire_time"] <= current_time:
            yield event.plain_result("❌ 授权已过期，请重新激活。")
            return

        remaining_days = (auth["expire_time"] - current_time) // 86400
        remaining_hours = ((auth["expire_time"] - current_time) % 86400) // 3600
        expire_date = time.strftime("%Y-%m-%d %H:%M", time.localtime(auth["expire_time"]))

        yield event.plain_result(f"""📋 授权信息
├─ 授权群组: {group_id}
├─ 剩余时间: {remaining_days} 天 {remaining_hours} 小时
└─ 到期时间: {expire_date}""")

    @filter.command("生成卡密")
    async def generate_keys(self, event: AstrMessageEvent) -> None:
        if not self.auth_key:
            yield event.plain_result("❌ 授权密钥未配置")
            return

        message = event.message_obj.content.strip()
        parts = message.split()
        days = self.default_days
        count = 1

        if len(parts) >= 2:
            try:
                days = int(parts[1])
            except ValueError:
                yield event.plain_result("❌ 天数必须是数字")
                return
        if len(parts) >= 3:
            try:
                count = min(int(parts[2]), 20)
            except ValueError:
                yield event.plain_result("❌ 数量必须是数字")
                return

        keys = []
        for i in range(count):
            key = generate_license_key(self.auth_key, days, "", i)
            keys.append(key)
            add_license_key(key, days, str(event.message_obj.sender.user_id))

        keys_text = "\n".join(keys)
        yield event.plain_result(f"""🎫 卡密生成成功
├─ 天数: {days} 天
├─ 数量: {count}
└─ 卡密:
{keys_text}""")

    @filter.command("帮助")
    async def show_help(self, event: AstrMessageEvent) -> None:
        help_text = """📖 SCUM 插件帮助

服务器查询:
  /服务器查询 <ID>    - 查询服务器状态
  /服务器详情 <ID>    - 查询服务器详细信息
  /搜索服务器 <关键词> - 搜索服务器
  /服务器排名         - 查看服务器排名

授权管理:
  /激活卡密 <卡密>    - 激活授权
  /授权查询           - 查看授权状态
  /生成卡密 <天数> [数量] - 生成卡密"""
        yield event.plain_result(help_text)
