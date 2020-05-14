import os
import requests

headers = {"Authorization": "token {}".format(os.environ['github_token'])}

def run_query(query): 
		request = requests.post('https://api.github.com/graphql', 
        json={'query': query}, headers=headers)
		if request.status_code == 200:
			return request.json()
		else:
			raise Exception("Query failed to run by returning code of {}. {}".format(
                    request.status_code, query))
                

def getDependencyAlerts(repo_owner, repo_name):
    query=''' 
        {
            repository(owner: "nasifimtiazohi" , name: "openmrs-core" ) {
                vulnerabilityAlerts(first: 10) {
                    nodes {
                        id
                    }
                }
            }
        }
    '''
    return run_query(query)
if __name__=='__main__':
    print(getDependencyAlerts('nasifimtiazohi','openmrs-core'))