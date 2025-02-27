from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
import urllib.parse
from typing import List, Dict
from pydantic import BaseModel, ValidationError
import logging
import traceback
from datetime import datetime
import uvicorn
import signal
import sys
import time
import warnings

# Suppress CryptographyDeprecationWarnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s - %(pathname)s:%(lineno)d',
    filename='api_server.log'
)
logger = logging.getLogger(__name__)

# MongoDB credentials
USERNAME = urllib.parse.quote_plus("zyraadmin")
PASSWORD = urllib.parse.quote_plus("Hacker@66202")
MONGO_URI = f"mongodb+srv://{USERNAME}:{PASSWORD}@zyracluster.9zq1b.mongodb.net/?retryWrites=true&w=majority&appName=ZyraCluster"

# Initialize FastAPI app
app = FastAPI(title="System Monitoring API", description="API to fetch and manage system monitoring data", version="1.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Middleware for request logging and timing
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    logger.info(f"Request started: {request.method} {request.url}")
    response = await call_next(request)
    duration = time.time() - start_time
    logger.info(f"Request completed: {request.method} {request.url} - Status: {response.status_code} - Duration: {duration:.3f}s")
    return response

# MongoDB client setup with connection pooling
client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000, maxPoolSize=10)

def get_db():
    try:
        global client
        client.admin.command('ping')  # Test connection
        return client["siem_db"]
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {str(e)} - {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Database connection failed")

# Pydantic models
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
    data: dict
    timestamp: str

# Helper function to serialize MongoDB documents
def serialize_doc(doc):
    try:
        if "_id" in doc:
            doc["_id"] = str(doc["_id"])
        return doc
    except Exception as e:
        logger.error(f"Error serializing document: {str(e)} - Document: {doc}")
        raise

# Generic data fetching function
async def fetch_device_data(device_id: str, data_type: str, limit: int = 100) -> List[MonitoringData]:
    db = None
    try:
        db = get_db()
        data_collection = db["device_data"]
        data = list(data_collection.find({"device_id": device_id, "type": data_type}).sort("timestamp", -1).limit(limit))
        if not data:
            logger.warning(f"No {data_type} data found for device {device_id}")
            raise HTTPException(status_code=404, detail=f"No {data_type} data found for device {device_id}")
        validated_data = []
        for doc in data:
            try:
                validated_data.append(MonitoringData(**serialize_doc(doc)))
            except ValidationError as ve:
                logger.warning(f"Invalid {data_type} data skipped: {str(ve)} - Data: {doc}")
        return validated_data
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Error fetching {data_type} data for {device_id}: {str(e)} - {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

# Endpoint to receive monitoring data from agent and update agent_status if applicable
@app.post("/api/v1/data", response_model=dict)
async def receive_monitoring_data(data: MonitoringData):
    db = None
    try:
        db = get_db()
        collection = db["device_data"]
        result = collection.insert_one(data.dict())
        logger.info(f"Stored {data.type} data for device {data.device_id} with ID: {result.inserted_id}")

        # Update agent_status collection if the data type is "agent_status"
        if data.type == "agent_status":
            status_collection = db["agent_status"]
            status_update = {
                "device_id": data.device_id,
                "hostname": data.hostname,
                "status": data.data.get("status", "unknown"),
                "last_seen": data.timestamp
            }
            status_collection.update_one(
                {"device_id": data.device_id},
                {"$set": status_update},
                upsert=True
            )
            logger.info(f"Updated agent_status for device {data.device_id} with status {status_update['status']}")

        return {"status": "success", "inserted_id": str(result.inserted_id)}
    except Exception as e:
        logger.error(f"Error storing data: {str(e)} - {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

# Existing endpoints
@app.get("/api/v1/agents/status", response_model=List[AgentStatus])
async def get_agent_status():
    db = None
    try:
        db = get_db()
        status_collection = db["agent_status"]
        agents = list(status_collection.find())
        if not agents:
            logger.warning("No agents found in agent_status collection")
            raise HTTPException(status_code=404, detail="No agents found")
        return [AgentStatus(**serialize_doc(agent)) for agent in agents]
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Error fetching agent status: {str(e)} - {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/api/v1/{device_id}/system", response_model=List[MonitoringData])
async def get_system_data(device_id: str, limit: int = 100):
    return await fetch_device_data(device_id, "system", limit)

@app.get("/api/v1/{device_id}/network", response_model=List[MonitoringData])
async def get_network_data(device_id: str, limit: int = 100):
    return await fetch_device_data(device_id, "network", limit)

@app.get("/api/v1/{device_id}/dns", response_model=List[MonitoringData])
async def get_dns_data(device_id: str, limit: int = 100):
    return await fetch_device_data(device_id, "dns_query", limit)

@app.get("/api/v1/{device_id}/login", response_model=List[MonitoringData])
async def get_login_data(device_id: str, limit: int = 100):
    return await fetch_device_data(device_id, "login_event", limit)

@app.get("/api/v1/{device_id}/login_anomaly", response_model=List[MonitoringData])
async def get_login_anomaly_data(device_id: str, limit: int = 100):
    return await fetch_device_data(device_id, "login_anomaly", limit)

@app.get("/api/v1/{device_id}/file_events", response_model=List[MonitoringData])
async def get_file_events_data(device_id: str, limit: int = 100):
    return await fetch_device_data(device_id, "file_event", limit)

@app.get("/api/v1/{device_id}/file_deletions", response_model=List[MonitoringData])
async def get_file_deletions_data(device_id: str, limit: int = 100):
    return await fetch_device_data(device_id, "file_deletion", limit)

@app.get("/api/v1/{device_id}/user_activity", response_model=List[MonitoringData])
async def get_user_activity_data(device_id: str, limit: int = 100):
    return await fetch_device_data(device_id, "user_activity", limit)

@app.get("/api/v1/{device_id}/registry_changes", response_model=List[MonitoringData])
async def get_registry_changes_data(device_id: str, limit: int = 100):
    return await fetch_device_data(device_id, "registry_change", limit)

@app.get("/api/v1/{device_id}/firewall_changes", response_model=List[MonitoringData])
async def get_firewall_changes_data(device_id: str, limit: int = 100):
    return await fetch_device_data(device_id, "firewall_change", limit)

@app.get("/api/v1/{device_id}/remote_commands", response_model=List[MonitoringData])
async def get_remote_commands_data(device_id: str, limit: int = 100):
    return await fetch_device_data(device_id, "remote_command", limit)

@app.get("/api/v1/{device_id}/service_events", response_model=List[MonitoringData])
async def get_service_events_data(device_id: str, limit: int = 100):
    return await fetch_device_data(device_id, "service_event", limit)

@app.get("/api/v1/{device_id}/service_alerts", response_model=List[MonitoringData])
async def get_service_alerts_data(device_id: str, limit: int = 100):
    return await fetch_device_data(device_id, "service_alert", limit)

@app.get("/api/v1/{device_id}/config_changes", response_model=List[MonitoringData])
async def get_config_changes_data(device_id: str, limit: int = 100):
    return await fetch_device_data(device_id, "config_change", limit)

@app.get("/api/v1/{device_id}/agent_alerts", response_model=List[MonitoringData])
async def get_agent_alerts_data(device_id: str, limit: int = 100):
    return await fetch_device_data(device_id, "agent_alert", limit)

@app.get("/api/v1/{device_id}/remote_responses", response_model=List[MonitoringData])
async def get_remote_responses_data(device_id: str, limit: int = 100):
    return await fetch_device_data(device_id, "remote_response", limit)

@app.get("/api/v1/{device_id}/uptime", response_model=List[MonitoringData])
async def get_uptime_data(device_id: str, limit: int = 100):
    return await fetch_device_data(device_id, "uptime", limit)

@app.get("/api/v1/{device_id}/reboot_events", response_model=List[MonitoringData])
async def get_reboot_events_data(device_id: str, limit: int = 100):
    return await fetch_device_data(device_id, "reboot_event", limit)

@app.get("/api/v1/{device_id}/agent_status", response_model=List[MonitoringData])
async def get_agent_status_data(device_id: str, limit: int = 100):
    return await fetch_device_data(device_id, "agent_status", limit)

@app.post("/api/v1/commands", response_model=CommandResponse)
async def send_command(command: CommandRequest):
    db = None
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
        logger.error(f"Error sending command to {command.device_id}: {str(e)} - {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/api/v1/{device_id}/commands", response_model=List[dict])
async def get_device_commands(device_id: str):
    db = None
    try:
        db = get_db()
        commands_collection = db["agent_commands"]
        commands = list(commands_collection.find({"device_id": device_id}))
        return [serialize_doc(cmd) for cmd in commands]
    except Exception as e:
        logger.error(f"Error fetching commands for {device_id}: {str(e)} - {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.put("/api/v1/commands/{command_id}")
async def update_command_status(command_id: str, update: dict):
    db = None
    try:
        db = get_db()
        commands_collection = db["agent_commands"]
        result = commands_collection.update_one({"_id": command_id}, {"$set": update})
        if result.modified_count == 0:
            raise HTTPException(status_code=404, detail="Command not found or no changes made")
        return {"status": "updated"}
    except Exception as e:
        logger.error(f"Error updating command {command_id}: {str(e)} - {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/api/v1/health")
async def health_check():
    db = None
    try:
        db = get_db()
        db.command("ping")
        return {"status": "healthy", "timestamp": datetime.now().isoformat()}
    except Exception as e:
        logger.error(f"Health check failed: {str(e)} - {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail="Database connection failed")

# Signal handler for graceful shutdown
def signal_handler(sig, frame):
    logger.info("Received shutdown signal, exiting gracefully...")
    client.close()
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")