import os
import requests

headers = {"Authorization": "token {}".format(os.environ['github_token'])}

def run_query(query, variables): 
        request = requests.post('https://api.github.com/graphql', 
        json={'query': query, 'variables':variables}, headers=headers)
        if request.status_code == 200:
            return request.json()['data']
        else:
            raise Exception("Query failed to run by returning code of {}. {}".format(
                    request.status_code, query))
                

def getDependencyAlerts(repo_owner, repo_name):
    query=''' 
            query($repo_owner: String!, $repo_name: String!, $after: String )  { 
                repository(owner: $repo_owner , name: $repo_name ) {
                    vulnerabilityAlerts(first:100, after: $after ) {
                        totalCount
                        nodes {
                            id
                            createdAt
                            dismissReason
                            dismissedAt
                            dismisser{
                                login
                            }
                            
                            securityAdvisory{
                            description
                            ghsaId
                            identifiers{
                                type
                                value
                            }
                            origin
                            publishedAt
                            severity
                            }
                        
                            
                            securityVulnerability{
                            package{
                                ecosystem
                                name
                            }
                            }
                            
                            
                            vulnerableManifestFilename
                            vulnerableManifestPath
                            vulnerableRequirements
                        }
                        pageInfo{
                            hasNextPage
                            endCursor
                        }
                    }
                }
    }
    '''
    variables={
            "repo_owner":repo_owner,
            "repo_name": repo_name,
            "after": None
            }

    totalCount=None
    alerts=[]
    while True:
        data=  run_query(query, variables)['repository']['vulnerabilityAlerts']
        totalCount=data['totalCount']
        alerts.extend(data['nodes'])
        if data['pageInfo']['hasNextPage']:
            variables["after"]=data['pageInfo']['endCursor']
        else:
            break

    if len(alerts)==totalCount:
        return alerts
    else:
        raise Exception('graphql call not functioning properly,')
if __name__=='__main__':
    print(getDependencyAlerts('RocketChat','Rocket.Chat'))
