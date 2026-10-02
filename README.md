# cloud_activity — 离线云活动回溯违规检测

仅用 Python 标准库（`sqlite3`、`bisect`、`dataclasses`）实现。事件集合在评估期间固定，
结果只取决于事件集合本身，与摄取顺序、批次划分无关。

## 策略（按 identity 统计，窗口为 `t-W < timestamp <= t`）

- `data_export_volume`：最近 60 分钟内 `data_export` 严格多于 50 条。
- `login_ip_fanout`：最近 15 分钟内 `login` 来自严格多于 3 个不同 IP
  （同一 IP 多条记录只算一个；旧记录到期时，该 IP 的较新记录仍可让它留在窗口内）。

`evaluate(start, end)` 输出策略持续成立的**最大连续左闭右开时间段**与查询范围
`[start, end)` 的非空交集，跨越边界的片段会被裁剪。同一毫秒的到期与新增整体计算，
不产生瞬时解除或零长片段；没有新事件时，记录到期也会让违规按时结束。

## 用法

```python
from cloud_activity import CloudActivityDetector

detector = CloudActivityDetector("events.db")   # 或 ":memory:"
detector.ingest([
    {"timestamp": 1_700_000_000_000, "identity": "alice",
     "action": "login", "source_ip": "203.0.113.7"},
    # ...可乱序、同毫秒多条、跨批插入
])
for v in detector.evaluate(start_ms, end_ms):
    print(v.identity, v.policy, v.start, v.end)
detector.close()
```

事件可以是 `dict`（含 `timestamp`/`identity`/`action`/`source_ip` 四个键，
时间为 UTC 毫秒整数，`action` 为 `"login"` 或 `"data_export"`），
也可以是 `cloud_activity.Event` 实例。返回的 `Violation` 含
`identity`、`policy`、`start`、`end` 字段，按 `(identity, policy, start)` 排序。

## 运行测试

```bash
python3 -m unittest discover -v
```

测试覆盖：同一毫秒到期+补入、同一 IP 多条不同时间记录、部分到期不提前移除 IP、
按时结束、阈值恰好相等、同时间戳事件跨批、从违规中间开始的查询、切分查询拼接
等于整体查询，以及固定随机种子乱序数据与独立朴素参考实现（`tests/naive_reference.py`）
的全量核对。
