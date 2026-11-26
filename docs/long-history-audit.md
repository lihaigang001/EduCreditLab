# 长账本回归复验

`results/long-history/` 保存 v1.3.0 和 v1.4.0 在 512、2,048 和 10,000 个区块下的配对测量。每对使用相同的已签名合成区块、四份本地验证副本和同一组回执。测试脚本在新目录内批量生成有效签名和完整链下证据，再用正式的历史查询、回执导出和离线验证入口测量读取。写入时延和正式网络吞吐量属于不同实验。

可直接将同目录的 `synthetic-10000-proof.json.gz` 导入工作台，使用 `synthetic-10000-fingerprint.txt` 中的合成网络指纹复验。预期输出为第 10,000 区块有效，复算得到 16 个学季学分。

安装软件后，在解压目录运行以下命令可复验。建议先在 v1.3.0 环境生成数据和测量基线，再对同一数据的副本使用 v1.4.0。每次选择一个新路径保存自建数据和结果。若只用 v1.4.0，生成和测量的新环境也可直接运行。

```bash
python tests/integration/long_history_audit.py build ./audit-fixture --height 2048
python tests/integration/long_history_audit.py measure ./audit-fixture --repeats 3 --out ./audit-samples.json
```

测量单位为毫秒和字节。`initial_history` 是单次首屏 HTTP 请求，`repeat_full_history` 是旧版的重复全量读取，`older_page` 是新版同一已验证视图的后续页。新版与旧版后两项完成同一浏览意图，客户端实际接收的记录数不同。`early_full_export` 生成第 4 区块的完整证明。最新回执体积使用 HTTP 下载的紧凑 JSON 字节数。原始 JSON 超过上传上限时，测试只提交长度头以验证拒收。离线测量包含文件内容解析和完整签名链核验。gzip 文件传输与 JSON 解码使用同一底层证明格式。

```bash
python -m unittest discover -s tests -q
```
