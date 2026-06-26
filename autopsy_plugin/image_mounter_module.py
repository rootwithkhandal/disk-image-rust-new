import jarray
import inspect
import os
import subprocess
from java.lang import System
from java.util.logging import Level
from org.sleuthkit.autopsy.ingest import IngestModuleAdapter
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.datamodel import Image

class ImageMounterFactory(IngestModuleFactoryAdapter):
    moduleName = "Image Mounter"
    
    def getModuleDisplayName(self):
        return self.moduleName
    
    def getModuleDescription(self):
        return "Mounts the data source image to the local filesystem using OS native tools."
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    def isDataSourceIngestModuleFactory(self):
        return True
    
    def createDataSourceIngestModule(self, ingestOptions):
        return ImageMounterModule()

class ImageMounterModule(DataSourceIngestModule):
    def __init__(self):
        self.context = None

    def startUp(self, context):
        self.context = context
        pass
        
    def process(self, dataSource, progressBar):
        progressBar.switchToIndeterminate()
        
        # Check if the data source is an Image
        if not isinstance(dataSource, Image):
            return IngestModuleAdapter.ProcessResult.OK
            
        # Get the paths
        paths = dataSource.getPaths()
        if not paths or len(paths) == 0:
            return IngestModuleAdapter.ProcessResult.OK
            
        image_path = paths[0]
        
        # Determine OS and mount
        os_name = System.getProperty("os.name").lower()
        
        try:
            if "win" in os_name:
                # Windows - Mount-DiskImage
                cmd = ["powershell", "-NoProfile", "-Command", "Mount-DiskImage", "-ImagePath", "'{}'".format(image_path)]
                subprocess.call(cmd)
            elif "mac" in os_name:
                # macOS
                cmd = ["hdiutil", "attach", image_path]
                subprocess.call(cmd)
            else:
                # Linux (requires sudo or permissions usually)
                cmd = ["losetup", "--find", "--partscan", image_path]
                subprocess.call(cmd)
                
            msg = IngestMessage.createMessage(IngestMessage.MessageType.INFO,
                ImageMounterFactory.moduleName,
                "Successfully mounted image: " + image_path)
            IngestServices.getInstance().postMessage(msg)
            
        except Exception as e:
            Logger.getLogger("Image Mounter").log(Level.SEVERE, "Error mounting image", e)
            msg = IngestMessage.createMessage(IngestMessage.MessageType.ERROR,
                ImageMounterFactory.moduleName,
                "Failed to mount image: " + str(e))
            IngestServices.getInstance().postMessage(msg)
            
        return IngestModuleAdapter.ProcessResult.OK
