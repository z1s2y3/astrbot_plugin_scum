import json
import os
import time
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any
from astrbot.core.utils.astrbot_path import get_astrbot_data_path
from astrbot.api import logger

def get_plugin_data_path():
    data_path = Path(get_astrbot_data_path()) / "plugin_data" / "scum"
    data_path.mkdir(parents=True, exist_ok=True)
    return data_path

def get_auth_file():
    return os.path.join(get_plugin_data_path(), "auth.json")

def get_license_keys_file():
    return os.path.join(get_plugin_data_path(), "license_keys.json")

def get_authorizations_file():
    return os.path.join(get_plugin_data_path(), "authorizations.json")

def get_bindings_file():
    return os.path.join(get_plugin_data_path(), "bindings.json")

def get_settings_file():
    return os.path.join(get_plugin_data_path(), "settings.json")

def generate_license_key(auth_key: str, days: int, group_id: str = "", index: int = 0) -> str:
    timestamp = int(time.time() * 1000)
    unique = hashlib.md5(f"{auth_key}{timestamp}{group_id}{index}".encode()).hexdigest()[:8]
    return f"JK{days}-{timestamp}{unique}".upper()

def verify_license_key(key: str, auth_key: str, group_id: str = "") -> dict:
    if not key.startswith("JK"):
        return {"valid": False, "error": "无效的卡密格式"}

    try:
        remaining = key[2:]
        if '-' in remaining:
            parts = remaining.split('-', 1)
            days_str = parts[0]
            rest = parts[1]
            if not days_str.isdigit():
                return {"valid": False, "error": "无效的卡密格式"}
            days = int(days_str)
            timestamp_str = rest[:13]
            unique = rest[13:]
        else:
            if len(remaining) < 21:
                return {"valid": False, "error": "无效的卡密格式"}
            days_str = remaining[:8]
            if not days_str.isdigit():
                return {"valid": False, "error": "无效的卡密格式"}
            days = int(days_str)
            timestamp_str = remaining[8:21]
            unique = remaining[21:]

        if not timestamp_str.isdigit():
            return {"valid": False, "error": "无效的卡密格式"}

        timestamp = int(timestamp_str)
        check_unique = hashlib.md5(f"{auth_key}{timestamp}{group_id}{0}".encode()).hexdigest()[:8]
        if unique != check_unique:
            for i in range(1, 100):
                check_unique = hashlib.md5(f"{auth_key}{timestamp}{group_id}{i}".encode()).hexdigest()[:8]
                if unique == check_unique:
                    return {"valid": True, "days": days, "timestamp": timestamp, "index": i}
            return {"valid": False, "error": "卡密验证失败"}

        return {"valid": True, "days": days, "timestamp": timestamp, "index": 0}
    except Exception as e:
        logger.error(f"验证卡密时出错: {e}")
        return {"valid": False, "error": str(e)}

def load_auth_config() -> dict:
    auth_file = get_auth_file()
    if os.path.exists(auth_file):
        try:
            with open(auth_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"加载授权配置失败: {e}")
    return {}

def save_auth_config(config: dict) -> None:
    auth_file = get_auth_file()
    try:
        with open(auth_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"保存授权配置失败: {e}")

def load_license_keys() -> dict:
    keys_file = get_license_keys_file()
    if os.path.exists(keys_file):
        try:
            with open(keys_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"加载卡密列表失败: {e}")
    return {}

def save_license_keys(keys: dict) -> None:
    keys_file = get_license_keys_file()
    try:
        with open(keys_file, 'w', encoding='utf-8') as f:
            json.dump(keys, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"保存卡密列表失败: {e}")

def add_license_key(key: str, days: int, creator: str = "system") -> bool:
    keys = load_license_keys()
    if key in keys:
        return False
    keys[key] = {
        "days": days,
        "creator": creator,
        "created_at": int(time.time()),
        "used": False,
        "used_at": None,
        "used_by": None
    }
    save_license_keys(keys)
    return True

def mark_key_as_used(key: str, user_id: str) -> bool:
    keys = load_license_keys()
    if key not in keys:
        return False
    keys[key]["used"] = True
    keys[key]["used_at"] = int(time.time())
    keys[key]["used_by"] = user_id
    save_license_keys(keys)
    return True

def is_key_used(key: str) -> bool:
    keys = load_license_keys()
    return key in keys and keys[key].get("used", False)

def load_authorizations() -> dict:
    auth_file = get_authorizations_file()
    if os.path.exists(auth_file):
        try:
            with open(auth_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"加载授权信息失败: {e}")
    return {}

def save_authorizations(authorizations: dict) -> None:
    auth_file = get_authorizations_file()
    try:
        with open(auth_file, 'w', encoding='utf-8') as f:
            json.dump(authorizations, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"保存授权信息失败: {e}")

def get_authorization(group_id: str) -> Optional[Dict[str, Any]]:
    authorizations = load_authorizations()
    return authorizations.get(group_id)

def set_authorization(group_id: str, expire_time: int, add_days: int = 0, operator_id: str = "") -> None:
    authorizations = load_authorizations()
    current_time = int(time.time())

    if group_id in authorizations:
        auth = authorizations[group_id]
        if auth["expire_time"] > current_time:
            auth["expire_time"] += add_days * 86400
        else:
            auth["expire_time"] = current_time + add_days * 86400
        auth["last_extended_at"] = current_time
        auth["last_extended_by"] = operator_id
    else:
        authorizations[group_id] = {
            "expire_time": current_time + add_days * 86400,
            "created_at": current_time,
            "last_extended_at": current_time,
            "last_extended_by": operator_id
        }

    save_authorizations(authorizations)

def extend_authorization(group_id: str, add_days: int, operator_id: str = "") -> bool:
    authorizations = load_authorizations()
    current_time = int(time.time())

    if group_id in authorizations:
        auth = authorizations[group_id]
        if auth["expire_time"] > current_time:
            auth["expire_time"] += add_days * 86400
        else:
            auth["expire_time"] = current_time + add_days * 86400
        auth["last_extended_at"] = current_time
        auth["last_extended_by"] = operator_id
        save_authorizations(authorizations)
        return True

    return False

def is_authorized(group_id: str) -> bool:
    authorizations = load_authorizations()
    if group_id not in authorizations:
        return False
    current_time = int(time.time())
    return authorizations[group_id]["expire_time"] > current_time

def get_expire_time(group_id: str) -> int:
    authorizations = load_authorizations()
    if group_id not in authorizations:
        return 0
    return authorizations[group_id].get("expire_time", 0)

def get_all_authorizations() -> dict:
    return load_authorizations()

def delete_authorization(group_id: str) -> bool:
    authorizations = load_authorizations()
    if group_id in authorizations:
        del authorizations[group_id]
        save_authorizations(authorizations)
        return True
    return False

def cleanup_expired_authorizations() -> int:
    authorizations = load_authorizations()
    current_time = int(time.time())
    expired_groups = [gid for gid, auth in authorizations.items() if auth["expire_time"] <= current_time]
    for gid in expired_groups:
        del authorizations[gid]
    if expired_groups:
        save_authorizations(authorizations)
    return len(expired_groups)

def load_settings() -> dict:
    settings_file = get_settings_file()
    if os.path.exists(settings_file):
        try:
            with open(settings_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"加载设置失败: {e}")
    return {}

def save_settings(settings: dict) -> None:
    settings_file = get_settings_file()
    try:
        with open(settings_file, 'w', encoding='utf-8') as f:
            json.dump(settings, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"保存设置失败: {e}")
