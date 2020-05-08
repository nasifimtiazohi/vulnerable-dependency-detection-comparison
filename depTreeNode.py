class depTreeNode():
    def __init__(self, group, artifact, version, packaging, scope=None, depth=None, parent=None):
        self.group=group
        self.artifact=artifact
        self.version=version
        self.packaging=packaging
        self.scope=scope
        self.depth=depth
        self.parent=parent
        self.children=None
    
    def getAttributes(self):
        return [self.group,self.artifact,self.version,self.packaging,
                self.scope,self.depth]

