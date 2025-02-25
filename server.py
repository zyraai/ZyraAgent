from fastapi import FastAPI, HTTPException
from pymongo import MongoClient
import urllib.parse
from typing import List, Dict
from pydantic import BaseModel
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='api_server.log'
)
logger = logging.getLogger(__name__)

# MongoDB credentials
USERNAME = urllib.parse.quote_plus("zyraadmin")
PASSWORD = urllib.parse.quote_plus("Hacker@66202")
MONGO_URI = f"mongodb+srv://{USERNAME}:{PASSWORD}@zyracluster.9zq1b.mongodb.net/?retryWrites=true&w=majority&appName=ZyraCluster"

# Initialize FastAPI app
app = FastAPI(title="System Monitoring API", description="API to fetch and manage system monitoring data", version="1.0")

# MongoDB client setup
def get_db():
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = client["siem_db"]
    return db

# Pydantic models for request/response validation
class CommandRequest(BaseModel):
    device_id: str
    command: str
    pid: int | None = None
    path: str | None = None

class CommandResponse(BaseModel):
    status: str
    command_id: str

class AgentStatus(BaseModel):
    device_id: str
    hostname: str
    status: str
    last_seen: str

class MonitoringData(BaseModel):
    device_id: str
    hostname: str
    type: str
    data: Dict
    timestamp: str

# Helper function to handle MongoDB ObjectId
def serialize_doc(doc):
    if "_id" in doc:
        doc["_id"] = str(doc["_id"])
    return doc

# GET Endpoints for Agent Status
@app.get("/api/v1/agents/status", response_model=List[AgentStatus])
async def get_agent_status():
    """Fetch status of all agents"""
    try:
        db = get_db()
        status_collection = db["agent_status"]
        agents = list(status_collection.find())
        if not agents:
            raise HTTPException(status_code=404, detail="No agents found")
        return [AgentStatus(**serialize_doc(agent)) for agent in agents]
    except Exception as e:
        logger.error(f"Error fetching agent status: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.client.close()

# GET Endpoints for Specific Data Types
@app.get("/api/v1/{device_id}/system", response_model=List[MonitoringData])
async def get_system_data(device_id: str, limit: int = 100):
    """Fetch system data for a specific device"""
    try:
        db = get_db()
        data_collection = db["device_data"]
        data = list(data_collection.find({"device_id": device_id, "type": "system"}).sort("timestamp", -1).limit(limit))
        if not data:
            raise HTTPException(status_code=404, detail=f"No system data found for device {device_id}")
        return [MonitoringData(**serialize_doc(doc)) for doc in data]
    except Exception as e:
        logger.error(f"Error fetching system data: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.client.close()

@app.get("/api/v1/{device_id}/network", response_model=List[MonitoringData])
async def get_network_data(device_id: str, limit: int = 100):
    """Fetch network data for a specific device"""
    try:
        db = get_db()
        data_collection = db["device_data"]
        data = list(data_collection.find({"device_id": device_id, "type": "network"}).sort("timestamp", -1).limit(limit))
        if not data:
            raise HTTPException(status_code=404, detail=f"No network data found for device {device_id}")
        return [MonitoringData(**serialize_doc(doc)) for doc in data]
    except Exception as e:
        logger.error(f"Error fetching network data: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.client.close()

@app.get("/api/v1/{device_id}/dns", response_model=List[MonitoringData])
async def get_dns_data(device_id: str, limit: int = 100):
    """Fetch DNS query data for a specific device"""
    try:
        db = get_db()
        data_collection = db["device_data"]
        data = list(data_collection.find({"device_id": device_id, "type": "dns_query"}).sort("timestamp", -1).limit(limit))
        if not data:
            raise HTTPException(status_code=404, detail=f"No DNS data found for device {device_id}")
        return [MonitoringData(**serialize_doc(doc)) for doc in data]
    except Exception as e:
        logger.error(f"Error fetching DNS data: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.client.close()

@app.get("/api/v1/{device_id}/login", response_model=List[MonitoringData])
async def get_login_data(device_id: str, limit: int = 100):
    """Fetch login event data for a specific device"""
    try:
        db = get_db()
        data_collection = db["device_data"]
        data = list(data_collection.find({"device_id": device_id, "type": "login_event"}).sort("timestamp", -1).limit(limit))
        if not data:
            raise HTTPException(status_code=404, detail=f"No login data found for device {device_id}")
        return [MonitoringData(**serialize_doc(doc)) for doc in data]
    except Exception as e:
        logger.error(f"Error fetching login data: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.client.close()

@app.get("/api/v1/{device_id}/login_anomaly", response_model=List[MonitoringData])
async def get_login_anomaly_data(device_id: str, limit: int = 100):
    """Fetch login anomaly data for a specific device"""
    try:
        db = get_db()
        data_collection = db["device_data"]
        data = list(data_collection.find({"device_id": device_id, "type": "login_anomaly"}).sort("timestamp", -1).limit(limit))
        if not data:
            raise HTTPException(status_code=404, detail=f"No login anomaly data found for device {device_id}")
        return [MonitoringData(**serialize_doc(doc)) for doc in data]
    except Exception as e:
        logger.error(f"Error fetching login anomaly data: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.client.close()

@app.get("/api/v1/{device_id}/file_events", response_model=List[MonitoringData])
async def get_file_events_data(device_id: str, limit: int = 100):
    """Fetch file event data for a specific device"""
    try:
        db = get_db()
        data_collection = db["device_data"]
        data = list(data_collection.find({"device_id": device_id, "type": "file_event"}).sort("timestamp", -1).limit(limit))
        if not data:
            raise HTTPException(status_code=404, detail=f"No file event data found for device {device_id}")
        return [MonitoringData(**serialize_doc(doc)) for doc in data]
    except Exception as e:
        logger.error(f"Error fetching file event data: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.client.close()

@app.get("/api/v1/{device_id}/file_deletions", response_model=List[MonitoringData])
async def get_file_deletions_data(device_id: str, limit: int = 100):
    """Fetch file deletion data for a specific device"""
    try:
        db = get_db()
        data_collection = db["device_data"]
        data = list(data_collection.find({"device_id": device_id, "type": "file_deletion"}).sort("timestamp", -1).limit(limit))
        if not data:
            raise HTTPException(status_code=404, detail=f"No file deletion data found for device {device_id}")
        return [MonitoringData(**serialize_doc(doc)) for doc in data]
    except Exception as e:
        logger.error(f"Error fetching file deletion data: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.client.close()

@app.get("/api/v1/{device_id}/user_activity", response_model=List[MonitoringData])
async def get_user_activity_data(device_id: str, limit: int = 100):
    """Fetch user activity data for a specific device"""
    try:
        db = get_db()
        data_collection = db["device_data"]
        data = list(data_collection.find({"device_id": device_id, "type": "user_activity"}).sort("timestamp", -1).limit(limit))
        if not data:
            raise HTTPException(status_code=404, detail=f"No user activity data found for device {device_id}")
        return [MonitoringData(**serialize_doc(doc)) for doc in data]
    except Exception as e:
        logger.error(f"Error fetching user activity data: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.client.close()

@app.get("/api/v1/{device_id}/registry_changes", response_model=List[MonitoringData])
async def get_registry_changes_data(device_id: str, limit: int = 100):
    """Fetch registry change data for a specific device"""
    try:
        db = get_db()
        data_collection = db["device_data"]
        data = list(data_collection.find({"device_id": device_id, "type": "registry_change"}).sort("timestamp", -1).limit(limit))
        if not data:
            raise HTTPException(status_code=404, detail=f"No registry change data found for device {device_id}")
        return [MonitoringData(**serialize_doc(doc)) for doc in data]
    except Exception as e:
        logger.error(f"Error fetching registry change data: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.client.close()

@app.get("/api/v1/{device_id}/firewall_changes", response_model=List[MonitoringData])
async def get_firewall_changes_data(device_id: str, limit: int = 100):
    """Fetch firewall change data for a specific device"""
    try:
        db = get_db()
        data_collection = db["device_data"]
        data = list(data_collection.find({"device_id": device_id, "type": "firewall_change"}).sort("timestamp", -1).limit(limit))
        if not data:
            raise HTTPException(status_code=404, detail=f"No firewall change data found for device {device_id}")
        return [MonitoringData(**serialize_doc(doc)) for doc in data]
    except Exception as e:
        logger.error(f"Error fetching firewall change data: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.client.close()

@app.get("/api/v1/{device_id}/remote_commands", response_model=List[MonitoringData])
async def get_remote_commands_data(device_id: str, limit: int = 100):
    """Fetch remote command data for a specific device"""
    try:
        db = get_db()
        data_collection = db["device_data"]
        data = list(data_collection.find({"device_id": device_id, "type": "remote_command"}).sort("timestamp", -1).limit(limit))
        if not data:
            raise HTTPException(status_code=404, detail=f"No remote command data found for device {device_id}")
        return [MonitoringData(**serialize_doc(doc)) for doc in data]
    except Exception as e:
        logger.error(f"Error fetching remote command data: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.client.close()

@app.get("/api/v1/{device_id}/service_events", response_model=List[MonitoringData])
async def get_service_events_data(device_id: str, limit: int = 100):
    """Fetch service event data for a specific device"""
    try:
        db = get_db()
        data_collection = db["device_data"]
        data = list(data_collection.find({"device_id": device_id, "type": "service_event"}).sort("timestamp", -1).limit(limit))
        if not data:
            raise HTTPException(status_code=404, detail=f"No service event data found for device {device_id}")
        return [MonitoringData(**serialize_doc(doc)) for doc in data]
    except Exception as e:
        logger.error(f"Error fetching service event data: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.client.close()

@app.get("/api/v1/{device_id}/service_alerts", response_model=List[MonitoringData])
async def get_service_alerts_data(device_id: str, limit: int = 100):
    """Fetch service alert data for a specific device"""
    try:
        db = get_db()
        data_collection = db["device_data"]
        data = list(data_collection.find({"device_id": device_id, "type": "service_alert"}).sort("timestamp", -1).limit(limit))
        if not data:
            raise HTTPException(status_code=404, detail=f"No service alert data found for device {device_id}")
        return [MonitoringData(**serialize_doc(doc)) for doc in data]
    except Exception as e:
        logger.error(f"Error fetching service alert data: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.client.close()

@app.get("/api/v1/{device_id}/config_changes", response_model=List[MonitoringData])
async def get_config_changes_data(device_id: str, limit: int = 100):
    """Fetch config change data for a specific device"""
    try:
        db = get_db()
        data_collection = db["device_data"]
        data = list(data_collection.find({"device_id": device_id, "type": "config_change"}).sort("timestamp", -1).limit(limit))
        if not data:
            raise HTTPException(status_code=404, detail=f"No config change data found for device {device_id}")
        return [MonitoringData(**serialize_doc(doc)) for doc in data]
    except Exception as e:
        logger.error(f"Error fetching config change data: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.client.close()

@app.get("/api/v1/{device_id}/agent_alerts", response_model=List[MonitoringData])
async def get_agent_alerts_data(device_id: str, limit: int = 100):
    """Fetch agent alert data for a specific device"""
    try:
        db = get_db()
        data_collection = db["device_data"]
        data = list(data_collection.find({"device_id": device_id, "type": "agent_alert"}).sort("timestamp", -1).limit(limit))
        if not data:
            raise HTTPException(status_code=404, detail=f"No agent alert data found for device {device_id}")
        return [MonitoringData(**serialize_doc(doc)) for doc in data]
    except Exception as e:
        logger.error(f"Error fetching agent alert data: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.client.close()

@app.get("/api/v1/{device_id}/remote_responses", response_model=List[MonitoringData])
async def get_remote_responses_data(device_id: str, limit: int = 100):
    """Fetch remote response data for a specific device"""
    try:
        db = get_db()
        data_collection = db["device_data"]
        data = list(data_collection.find({"device_id": device_id, "type": "remote_response"}).sort("timestamp", -1).limit(limit))
        if not data:
            raise HTTPException(status_code=404, detail=f"No remote response data found for device {device_id}")
        return [MonitoringData(**serialize_doc(doc)) for doc in data]
    except Exception as e:
        logger.error(f"Error fetching remote response data: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.client.close()

@app.get("/api/v1/{device_id}/uptime", response_model=List[MonitoringData])
async def get_uptime_data(device_id: str, limit: int = 100):
    """Fetch uptime data for a specific device"""
    try:
        db = get_db()
        data_collection = db["device_data"]
        data = list(data_collection.find({"device_id": device_id, "type": "uptime"}).sort("timestamp", -1).limit(limit))
        if not data:
            raise HTTPException(status_code=404, detail=f"No uptime data found for device {device_id}")
        return [MonitoringData(**serialize_doc(doc)) for doc in data]
    except Exception as e:
        logger.error(f"Error fetching uptime data: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.client.close()

@app.get("/api/v1/{device_id}/reboot_events", response_model=List[MonitoringData])
async def get_reboot_events_data(device_id: str, limit: int = 100):
    """Fetch reboot event data for a specific device"""
    try:
        db = get_db()
        data_collection = db["device_data"]
        data = list(data_collection.find({"device_id": device_id, "type": "reboot_event"}).sort("timestamp", -1).limit(limit))
        if not data:
            raise HTTPException(status_code=404, detail=f"No reboot event data found for device {device_id}")
        return [MonitoringData(**serialize_doc(doc)) for doc in data]
    except Exception as e:
        logger.error(f"Error fetching reboot event data: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.client.close()

@app.get("/api/v1/{device_id}/agent_status", response_model=List[MonitoringData])
async def get_agent_status_data(device_id: str, limit: int = 100):
    """Fetch agent status data for a specific device"""
    try:
        db = get_db()
        data_collection = db["device_data"]
        data = list(data_collection.find({"device_id": device_id, "type": "agent_status"}).sort("timestamp", -1).limit(limit))
        if not data:
            raise HTTPException(status_code=404, detail=f"No agent status data found for device {device_id}")
        return [MonitoringData(**serialize_doc(doc)) for doc in data]
    except Exception as e:
        logger.error(f"Error fetching agent status data: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.client.close()

# POST Endpoint for Commands
@app.post("/api/v1/commands", response_model=CommandResponse)
async def send_command(command: CommandRequest):
    """Send a command to an agent"""
    try:
        db = get_db()
        commands_collection = db["agent_commands"]
        cmd_doc = {
            "device_id": command.device_id,
            "command": command.command,
            "pid": command.pid,
            "path": command.path,
            "processed": False,
            "timestamp": datetime.now().isoformat()
        }
        result = commands_collection.insert_one(cmd_doc)
        logger.info(f"Command sent to {command.device_id}: {command.command}")
        return CommandResponse(status="sent", command_id=str(result.inserted_id))
    except Exception as e:
        logger.error(f"Error sending command: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.client.close()

# Health Check
@app.get("/api/v1/health")
async def health_check():
    """Check API server health"""
    try:
        db = get_db()
        db.command("ping")
        return {"status": "healthy", "timestamp": datetime.now().isoformat()}
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=500, detail="Database connection failed")
    finally:
        db.client.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")