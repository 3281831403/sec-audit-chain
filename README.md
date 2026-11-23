# sec-audit-chain

## 题面

审计日志被人删掉中间两行，校验工具仍然报告整条链完好：单条哈希不包含前一条哈希，链退化为独立哈希；哈希的字段拼接没有分隔，字段内容可以转移；追加时序列号从零开始但校验要求从一开始，整体错位；校验只比对每条自身哈希，不校验前哈希链接；校验遇到第一个断点继续遍历，返回最后一个断点；截断检测用当前长度与记录数比较，结果恒为假；乱序检测只看首尾序列号，中间乱序漏检；时间间隔检测用绝对时间而不是相邻差，阈值失效；链校验不检查哈希长度，截断哈希通过；批量校验复用前哈希，后一条链继承前一条链的尾部。audit/chain.py 是核心，tests/test_chain.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

## 运行方式

```powershell
cd D:\gsb-20261119\sec-audit-chain
python -m pytest tests -q
```

初始状态应恰好为：

```text
15 failed
```

15 个失败必须全部来自测试调用 audit/chain.py 中 raise NotImplementedError 的桩函数；不允许出现 collection error、import error 或 syntax error，也不允许跳过测试。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## 目录

```text
sec-audit-chain/
  README.md
  conftest.py
  .gitignore
  audit/__init__.py
  audit/chain.py
  tests/test_chain.py
```

## 约束

- 只使用标准库（hashlib、json、hmac）与 pytest，离线运行，不使用随机数。
- audit/chain.py 的 8 个函数当前全部是桩；函数契约写在各函数 docstring 中，容差为 0：哈希必须覆盖前一条哈希、字段边界必须无歧义、序列号必须从一开始、断点必须取首个、截断与乱序与时间窗都必须报出、批量校验各链独立。
- tests/test_chain.py 是不可修改的验收标准；不要改测试、加 skip/xfail、放宽断言或加 monkeypatch 来制造绿色，只实现 audit/chain.py。
- 不得联网，不得引入第三方依赖。
