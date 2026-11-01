"""一次性账户初始化；密码材料只允许通过标准输入传入。"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from typing import Any

from pydantic import ValidationError

from .models import UserCreate
from .security import hash_password, utc_text
from .store import Store


def bootstrap(database_path: str, payload: Any) -> int:
    records = payload.get("users") if isinstance(payload, dict) else payload
    if not isinstance(records, list) or not records:
        raise ValueError("标准输入 JSON 必须是非空账户数组，或包含 users 数组的对象")
    try:
        users = [UserCreate.model_validate(record) for record in records]
    except ValidationError as error:
        raise ValueError("标准输入 JSON 包含无效账户记录") from error
    if len({item.username for item in users}) != len(users):
        raise ValueError("标准输入 JSON 包含重复账户名")
    store = Store(database_path)
    store.initialize()
    with store.write_transaction() as connection:
        existing = connection.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
        if existing:
            raise ValueError("账户初始化只能对没有账户的数据库执行")
        now = utc_text()
        try:
            for user in users:
                connection.execute(
                    "INSERT INTO users(username, password_hash, role, active, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?)",
                    (user.username, hash_password(user.password.get_secret_value()), user.role, now, now),
                )
                connection.executemany(
                    "INSERT INTO user_networks(username, network) VALUES (?, ?)",
                    [(user.username, network) for network in user.networks],
                )
        except sqlite3.IntegrityError as error:
            raise ValueError("账户初始化无法创建账户记录") from error
    return len(users)


def main() -> int:
    parser = argparse.ArgumentParser(description="通过标准输入 JSON 初始化测试环境的 VPN 账户。")
    parser.add_argument("--database", required=True, help="SQLite 数据库路径（不含秘密）")
    arguments = parser.parse_args()
    try:
        payload = json.load(sys.stdin)
        count = bootstrap(arguments.database, payload)
    except (ValueError, json.JSONDecodeError) as error:
        print(f"账户初始化失败：{error}", file=sys.stderr)
        return 2
    print(f"已初始化 {count} 个账户")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
