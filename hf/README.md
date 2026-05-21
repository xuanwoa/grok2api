# Hugging Face Space 部署说明

这个目录用于准备 Hugging Face Docker Space 的部署文件。上传到 Hugging Face Space 时，只需要把 `hf/Dockerfile` 的内容放到 Space 仓库根目录并命名为 `Dockerfile`；本 README 仅作为本仓库内的部署备忘，不需要上传。

## 部署步骤

1. 确认 GitHub Actions 已经把主项目镜像推送到 GHCR，例如 `ghcr.io/chenyme/grok2api:latest`。
2. 在 Hugging Face 创建 Docker Space。
3. 将 `hf/Dockerfile` 上传到 Space 仓库根目录，文件名保持为 `Dockerfile`。
4. 创建或绑定 Hugging Face Storage Bucket。
5. 将 bucket 以 read-write 方式挂载到容器路径 `/data`。
6. 重启 Space。

## 端口与持久化

- Hugging Face Docker Space 默认使用端口 `7860`，`hf/Dockerfile` 已将服务端口设置为 `7860`。
- bucket 挂载到 `/data` 后，下列内容会持久化：
  - `/data/config.toml`
  - `/data/accounts.db`
  - `/data/files/...`
  - `/data/cache/local_media_cache.db`

## 注意事项

- 如果 GHCR 镜像包是 private，需要让 Hugging Face Space 能够拉取该镜像，或将镜像包改为 public。
- 当前配置使用本地 SQLite 存储，适合单实例 Space。多实例并发写入时，建议改用 Redis 或 PostgreSQL 等外部存储。
