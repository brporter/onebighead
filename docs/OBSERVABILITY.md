# Observability

OneBigHead uses OpenTelemetry for traces, metrics, and structured logs. The telemetry pipeline adapts to the environment automatically.

## Local Development (Rider)

In local development, JetBrains Rider's [OpenTelemetry plugin](https://plugins.jetbrains.com/plugin/27488-opentelemetry) provides in-IDE observability with zero configuration.

### Setup

1. Install the **OpenTelemetry** plugin from the JetBrains Marketplace (Settings > Plugins > Marketplace)
2. Open the project in Rider and run the backend using **Run** (not Debug)

Rider automatically sets `OTEL_EXPORTER_OTLP_ENDPOINT` when launching the app. The backend detects this and sends traces, metrics, and logs to Rider's built-in OTLP receiver.

### What you get

- **Logs** - Structured log viewer with filtering by level, text search, and click-through to source code
- **Metrics** - Runtime metrics visualization (GC, thread pool, HTTP requests)
- **Traces** - Request traces with span details and architecture diagrams generated from execution traces

### Notes

- Auto-instrumentation only works with **Run**, not **Debug**
- If running from the terminal (`dotnet run`), telemetry goes nowhere unless you set `OTEL_EXPORTER_OTLP_ENDPOINT` yourself
- The `docker-compose.yml` only runs PostgreSQL; there is no local OTel stack to manage

---

## Production (Azure)

In production, telemetry flows to Azure Monitor (Application Insights) and is visualized in Azure Managed Grafana.

### Architecture

```
ASP.NET Core App
  |
  |-- Azure Monitor Trace Exporter --> Application Insights --> Log Analytics Workspace
  |-- Azure Monitor Metric Exporter --> Application Insights --> Log Analytics Workspace
  |-- Azure Monitor Log Exporter ----> Application Insights --> Log Analytics Workspace
  |
  |-- Prometheus /metrics endpoint (available but not actively scraped)
```

Azure Managed Grafana reads from Application Insights via the Azure Monitor datasource.

### How it activates

The backend checks for `APPLICATIONINSIGHTS_CONNECTION_STRING` at startup. When present, it registers Azure Monitor exporters for traces, metrics, and logs. When absent (local dev), those exporters are simply not registered.

In production, set the variable in `/opt/onebighead/.env` on the VM (see `deploy/vm/.env.example`).

### Azure Monitor resources

Telemetry flows into the following Azure resources (provision them manually or reuse existing ones):

| Resource | Naming Convention | Purpose |
|----------|-------------------|---------|
| Log Analytics Workspace | `<app-name>-logs` | Backing store for Application Insights data, queryable via KQL |
| Application Insights | `<app-name>-appinsights` | Application telemetry (traces, metrics, logs, exceptions) |
| Azure Managed Grafana | `<app-name>-grafana` | Dashboard visualization with Azure Monitor datasource |

The Grafana instance needs **Monitoring Reader** RBAC on the resource group, allowing it to query Application Insights data.

---

## Setting Up the Grafana Dashboard

Once telemetry is flowing into Application Insights, import the pre-built dashboard to visualize application health.

### Step 1: Get your Grafana URL

```bash
APP_NAME="<your-app-name>"
az grafana show --name "${APP_NAME}-grafana" \
    --resource-group "${APP_NAME}-rg" \
    --query "properties.endpoint" -o tsv
```

Open this URL in your browser. You'll authenticate with your Azure AD account.

### Step 2: Add Azure Monitor datasource (if not auto-configured)

Azure Managed Grafana usually auto-discovers Azure Monitor. Verify:

1. Go to **Connections** > **Data sources**
2. Look for **Azure Monitor** - it should already be listed
3. If not, click **Add data source** > **Azure Monitor** > **Save & test**

### Step 3: Get your Application Insights resource ID

```bash
APP_NAME="<your-app-name>"
az monitor app-insights component show \
    --app "${APP_NAME}-appinsights" \
    --resource-group "${APP_NAME}-rg" \
    --query id -o tsv
```

This returns a string like:
```
/subscriptions/<sub-id>/resourceGroups/<rg>/providers/microsoft.insights/components/<app-name>-appinsights
```

### Step 4: Import the dashboard

1. In Grafana, go to **Dashboards** > **New** > **Import**
2. Upload or paste the contents of `backend/grafana/dashboard.json`
3. Click **Import**

### Step 5: Configure dashboard variables

After import, the dashboard has two template variables at the top:

- **Data Source** (`ds`) - Select your **Azure Monitor** datasource from the dropdown
- **Resource** (`resource`) - Paste the Application Insights resource ID from Step 3

### Dashboard panels

| Section | What it shows |
|---------|---------------|
| **Request Health** | Success rate, request volume, avg/P95/P99 response times, success vs failure over time |
| **Errors** | Error rate trend, errors by HTTP status code, top exceptions |
| **By Workspace (Tenant)** | Request volume, latency, and error rate broken down by `workspace_id` |
| **Most Expensive Requests** | Slowest endpoints by P95, most total server time consumed, slowest SQL queries |
| **ASP.NET Runtime Health** | GC collections by generation, heap size, thread pool threads/queue length, active connections, exception count |

---

## Querying telemetry directly

You can query Application Insights data without Grafana using KQL in the Azure Portal.

### Open the query editor

```bash
APP_NAME="<your-app-name>"
# Open Application Insights in portal
az monitor app-insights component show \
    --app "${APP_NAME}-appinsights" \
    --resource-group "${APP_NAME}-rg" \
    --query "id" -o tsv
```

Navigate to Application Insights in the Azure Portal, then click **Logs** in the sidebar.

### Useful KQL queries

**Request success rate over the last hour:**
```kql
requests
| where timestamp > ago(1h)
| summarize success_rate = round(100.0 * countif(success == true) / count(), 2)
```

**Slowest endpoints:**
```kql
requests
| where timestamp > ago(1h)
| summarize p95 = percentile(duration, 95), count() by name
| order by p95 desc
| take 10
```

**Errors by workspace:**
```kql
dependencies
| where timestamp > ago(1h)
| where success == false
| where isnotempty(customDimensions.workspace_id)
| summarize count() by tostring(customDimensions.workspace_id)
| order by count_ desc
```

**Correlated logs for a specific trace:**
```kql
traces
| where operation_Id == "<trace-id>"
| order by timestamp asc
```

---

## Telemetry correlation

Structured logs emitted via `ILogger` are automatically correlated with traces. In Application Insights or Grafana, you can:

1. Find a slow request in the **requests** table
2. Copy its `operation_Id`
3. Query the **traces** table for that `operation_Id` to see all logs from that request
4. Query the **dependencies** table for that `operation_Id` to see SQL queries and HTTP calls

The `workspace_id` custom dimension is set on repository and service spans by the auto-generated tracing proxies, enabling per-tenant analysis.
