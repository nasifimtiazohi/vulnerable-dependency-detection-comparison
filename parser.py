from DepTreeNode import DepTreeNode

def parseCanonicalForm(s):
    s=s.split(":")
    if len(s)  < 4:
        raise Exception("invalid data")

    #in maven log, packaging comes before version
    group, artifact, packaging, version, scope = s[0], s[1], s[2], s[3], None

    if len(s) == 5:
        scope = s[4]
    
    return group, artifact, version,  packaging, scope
    
def processLines(filename):
    file=open(filename,'r')
    Tree=[]
    for line in file:
        Tree.append(line.replace('\n',''))
    return Tree

def buildTree(Tree):
    root=None
    if not Tree:
        raise Exception('blank file')
    group, artifact, version,  packaging, scope = parseCanonicalForm(Tree[0])
    root = DepTreeNode(group, artifact, version,  packaging, scope, depth=0)
    root.children=Tree[1:]

    curLevel=[root]
    depth=0

    #implement BFS
    while curLevel:
        depth+=1 #processing next level
        nextLevel=[] #put nodes of direct children here
        for node in curLevel:
            directChildren=[]
            indexes=[] #get the indexes of direct child in node.children
            for i in range(0,len(node.children)):
                node.children[i]=node.children[i][3:] #3 characters preced for each level
                line=node.children[i]
                #if not (line[0]=='\\' or line[0]=='+' or line[0]=='|' or line[0]=='-' or line[0]==' '):
                #TODO: may not work for all extended maven formats
                if line[0].isalpha():
                    indexes.append(i)

            for i in range(0,len(indexes)):
                group, artifact, version,  packaging, scope = parseCanonicalForm(node.children[indexes[i]])
                child = DepTreeNode(group, artifact, version,  packaging, scope, depth, node)
                if i != len(indexes) - 1:
                    #if not last node
                    child.children=node.children[indexes[i]+1:indexes[i+1]]
                else:
                    child.children=node.children[indexes[i]+1:]
                directChildren.append(child)

            node.children=directChildren
            nextLevel.extend(node.children)
        curLevel=nextLevel
    return root

def write2dict(root):
    headers=DepTreeNode.getAttributesHeaders()
    data=[]
    def recursion(root):
        nonlocal data
        data.append( root.getAttributes())
        for child in root.children:
            recursion(child)
    recursion(root)
    
    project= ':'.join(data[0][0:3])
    d={'project':project, 'dependencies':{}}

    data=data[1:]
    if data:
        if len(data[0]) != 6:
            raise Exception("data row does not have six columns") 
        data=list(map(list, zip(*data)))
        for i,k in enumerate(headers):
            d['dependencies'][k]=data[i]
    return d


def dependencyTree2dict(filename):
    Tree=processLines(filename)
    root=buildTree(Tree)
    d=write2dict(root)
    return d

if __name__=='__main__':
    d=dependencyTree2dict('./testcases/deproot.txt')
    print(d)
    
        


