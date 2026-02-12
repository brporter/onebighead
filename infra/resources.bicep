@minLength(3)
@maxLength(16)
@description('Base name for all resources')
param appName string

@description('Azure region for all resources')
param location string

@description('Entra ID object ID for SQL admin')
param sqlAdAdminObjectId string

@description('Entra ID display name for SQL admin')
param sqlAdAdminDisplayName string

@description('Whether to deploy the Container App (set false when re-provisioning infra only)')
param deployContainerApp bool = true

@description('Azure region for Grafana (not all regions support it)')
param grafanaLocation string = location

@description('Skip role assignments on re-runs (they error if they already exist)')
param skipRoleAssignments bool = false

// Deterministic suffix for globally unique SQL server name
var uniqueSuffix = substring(uniqueString(resourceGroup().id), 0, 6)

// Connection string for managed identity authentication
var sqlConnectionString = 'Server=tcp:${sqlServer.properties.fullyQualifiedDomainName},1433;Database=${appName};Authentication=Active Directory Managed Identity;User Id=${identity.properties.clientId};Encrypt=True;TrustServerCertificate=False;'

// 1. Container Registry
resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: '${appName}acr'
  location: location
  sku: {
    name: 'Basic'
  }
}

// 2. User-Assigned Managed Identity
resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${appName}-identity'
  location: location
}

// 3. Role Assignment: AcrPull for identity on ACR
resource acrPullRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!skipRoleAssignments) {
  name: guid(acr.id, identity.id, 'AcrPull')
  scope: acr
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d') // AcrPull
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// 4. SQL Server (Entra-only authentication)
resource sqlServer 'Microsoft.Sql/servers@2023-08-01-preview' = {
  name: '${appName}-sql-${uniqueSuffix}'
  location: location
  properties: {
    administrators: {
      administratorType: 'ActiveDirectory'
      azureADOnlyAuthentication: true
      login: sqlAdAdminDisplayName
      sid: sqlAdAdminObjectId
      tenantId: tenant().tenantId
      principalType: 'User'
    }
    minimalTlsVersion: '1.2'
  }
}

// 5. SQL Database
resource sqlDatabase 'Microsoft.Sql/servers/databases@2023-08-01-preview' = {
  parent: sqlServer
  name: appName
  location: location
  sku: {
    name: 'GP_S_Gen5'
    tier: 'GeneralPurpose'
    family: 'Gen5'
    capacity: 1
  }
  properties: {
    autoPauseDelay: 60
    minCapacity: json('0.5')
  }
}

// 6. SQL Firewall Rule: Allow Azure Services
resource sqlFirewallRule 'Microsoft.Sql/servers/firewallRules@2023-08-01-preview' = {
  parent: sqlServer
  name: 'AllowAzureServices'
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '0.0.0.0'
  }
}

// 7. Log Analytics Workspace
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${appName}-logs'
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
  }
}

// 8. Application Insights
resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: '${appName}-appinsights'
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalytics.id
  }
}

// 9. Container Apps Environment
resource containerEnv 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: '${appName}-env'
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalytics.properties.customerId
        sharedKey: logAnalytics.listKeys().primarySharedKey
      }
    }
    workloadProfiles: [
      {
        name: 'Consumption'
        workloadProfileType: 'Consumption'
      }
    ]
  }
}

// 10. Azure Managed Grafana
resource grafana 'Microsoft.Dashboard/grafana@2023-09-01' = {
  name: '${appName}-grafana'
  location: grafanaLocation
  sku: {
    name: 'Standard'
  }
  identity: {
    type: 'SystemAssigned'
  }
  properties: {}
}

// 11. Role Assignment: Monitoring Reader for Grafana on resource group
// Include grafanaLocation in the GUID so a region change produces a new assignment name
resource grafanaMonitoringRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!skipRoleAssignments) {
  name: guid(resourceGroup().id, grafana.id, grafanaLocation, 'MonitoringReader')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '43d0d8ad-25c7-4714-9337-8ba259a9fe05') // Monitoring Reader
    principalId: grafana.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// 12. Container App (conditional — omit on infra-only re-runs)
resource containerApp 'Microsoft.App/containerApps@2024-03-01' = if (deployContainerApp) {
  name: '${appName}-app'
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identity.id}': {}
    }
  }
  properties: {
    managedEnvironmentId: containerEnv.id
    configuration: {
      ingress: {
        external: true
        targetPort: 8080
      }
      registries: [
        {
          server: acr.properties.loginServer
          identity: identity.id
        }
      ]
    }
    template: {
      containers: [
        {
          name: appName
          image: 'mcr.microsoft.com/k8se/quickstart:latest'
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          env: [
            { name: 'ASPNETCORE_ENVIRONMENT', value: 'Production' }
            { name: 'ConnectionStrings__DefaultConnection', value: sqlConnectionString }
            { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: appInsights.properties.ConnectionString }
          ]
        }
      ]
      scale: {
        minReplicas: 0
        maxReplicas: 1
      }
    }
  }
}

// Outputs
output acrLoginServer string = acr.properties.loginServer
output acrName string = acr.name
output sqlServerName string = sqlServer.name
output sqlServerFqdn string = sqlServer.properties.fullyQualifiedDomainName
output sqlDatabaseName string = sqlDatabase.name
output identityName string = identity.name
output identityClientId string = identity.properties.clientId
output identityId string = identity.id
output containerEnvName string = containerEnv.name
output appInsightsConnectionString string = appInsights.properties.ConnectionString
output grafanaEndpoint string = grafana.properties.endpoint
output containerAppName string = deployContainerApp ? containerApp!.name : ''
output containerAppFqdn string = deployContainerApp ? containerApp!.properties.configuration.ingress.fqdn : ''
