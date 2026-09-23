# WeCom Chat Agent Readonly

A local, read-only Windows collector and MCP server for searching chat history visible to the currently signed-in WeCom account.

The project creates a local snapshot of supported WeCom databases, builds a SQLite search index, and exposes bounded MCP tools for conversations, messages, search, context, recent messages, and locally cached attachments. It does not send messages or modify WeCom source databases.

## Security model

- Database keys are read from the running WeCom process, validated against the database, kept in memory, and never logged or stored.
- Source databases and WAL files are copied before processing. Unknown formats fail closed.
- The MCP index opens in SQLite read-only mode. The attachment tool only copies uniquely matched files from the selected account's `Cache\Image` or `Cache\File` tree into the archive.
- Local archive data contains chat text and may contain extracted attachments. Keep the archive outside the repository and restrict access appropriately.
- Do not commit `config.json`, `index.db`, attachments, logs, database snapshots, or decrypted databases. These paths are covered by `.gitignore`.

This implementation is version-sensitive. It was developed against a WeCom 5.0.x Windows database layout. Revalidate compatibility after WeCom upgrades.

## Requirements

- Windows 10 or later
- WeCom desktop signed in and running
- Python 3.11 or later
- Permission to read the current user's WeCom process and files

Install dependencies:

```powershell
py -3 -m venv .venv
& '.\.venv\Scripts\python.exe' -m pip install -r requirements.txt
```

## Collect

Find the signed-in account's `Data` directory. It normally sits below the user-selected WeCom document directory as `WXWork\<account-id>\Data`. Store the archive in a separate directory.

```powershell
& '.\collect.ps1' `
  -SourceDir 'D:\WXWork\ACCOUNT_ID\Data' `
  -DataDir 'D:\WeComAgentArchive'
```

The first run indexes all readable history. Later runs enumerate source message IDs and insert only unseen messages, so messages written late with older timestamps are still discovered.

Optional scheduled refresh:

```powershell
& '.\install-schedule.ps1' `
  -SourceDir 'D:\WXWork\ACCOUNT_ID\Data' `
  -DataDir 'D:\WeComAgentArchive' `
  -IntervalMinutes 15
```

## MCP configuration

The server uses stdio. Replace the example paths with absolute local paths.

```json
{
  "mcpServers": {
    "wecom-chat-readonly": {
      "command": "D:\\path\\to\\.venv\\Scripts\\python.exe",
      "args": [
        "D:\\path\\to\\server.py",
        "--data-dir",
        "D:\\WeComAgentArchive"
      ]
    }
  }
}
```

Available tools:

- `wecom_status`
- `wecom_conversations`
- `wecom_messages`
- `wecom_search`
- `wecom_context`
- `wecom_attachment`
- `wecom_since`

Queries are paginated and capped at 100 records per call. A useful agent flow is search, context, then attachment retrieval for relevant media messages.

## Known limitations

- Message formats and database layouts are undocumented and can change between WeCom releases.
- Some message types, names, group nicknames, and attachments may remain unresolved.
- A uniquely matched cached filename is useful evidence but does not replace manual verification for consequential decisions.
- The collector covers only chat data visible to the signed-in local account. It is not an enterprise compliance archive.
- Large-scale performance and completeness require validation against the target machine and WeCom client.

## Privacy-safe issue reports

Before filing an issue, remove chat text, names, account IDs, email addresses, phone numbers, local paths, database pages, keys, logs, screenshots, and attachments. Prefer synthetic fixtures and aggregate counts.

