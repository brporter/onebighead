targetScope = 'subscription'

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

resource rg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: '${appName}-rg'
  location: location
}

module resources 'resources.bicep' = {
  name: 'resources'
  scope: rg
  params: {
    appName: appName
    location: location
    sqlAdAdminObjectId: sqlAdAdminObjectId
    sqlAdAdminDisplayName: sqlAdAdminDisplayName
    deployContainerApp: deployContainerApp
    grafanaLocation: grafanaLocation
    skipRoleAssignments: skipRoleAssignments
  }
}

output acrLoginServer string = resources.outputs.acrLoginServer
output acrName string = resources.outputs.acrName
output sqlServerName string = resources.outputs.sqlServerName
output sqlServerFqdn string = resources.outputs.sqlServerFqdn
output sqlDatabaseName string = resources.outputs.sqlDatabaseName
output identityName string = resources.outputs.identityName
output identityClientId string = resources.outputs.identityClientId
output identityId string = resources.outputs.identityId
output containerEnvName string = resources.outputs.containerEnvName
output appInsightsConnectionString string = resources.outputs.appInsightsConnectionString
output grafanaEndpoint string = resources.outputs.grafanaEndpoint
output containerAppName string = resources.outputs.containerAppName
output containerAppFqdn string = resources.outputs.containerAppFqdn
