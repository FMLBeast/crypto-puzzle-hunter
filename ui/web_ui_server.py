"""
Web UI Server for Crypto Hunter
Provides a beautiful real-time interface to monitor analysis progress
"""

import asyncio
import json
import os
import time
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

import websockets
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
import uvicorn

from core.state import State
from core.logger import solution_logger
from core.enhanced_state_saver import EnhancedStateSaver

class WebUIManager:
    """Manages the web UI and real-time updates"""
    
    def __init__(self):
        self.app = FastAPI(title="Crypto Hunter Dashboard")
        self.active_connections: List[WebSocket] = []
        self.current_analysis_id: Optional[str] = None
        self.analysis_data: Dict[str, Any] = {}
        self.setup_routes()
        
    def setup_routes(self):
        """Setup FastAPI routes"""
        
        # Static files and templates directory
        ui_dir = Path(__file__).parent
        static_dir = ui_dir / "static"
        templates_dir = ui_dir / "templates"
        
        # Create directories if they don't exist
        static_dir.mkdir(exist_ok=True)
        templates_dir.mkdir(exist_ok=True)
        
        # Mount static files
        self.app.mount("/static", StaticFiles(directory=static_dir), name="static")
        self.templates = Jinja2Templates(directory=templates_dir)
        
        @self.app.get("/", response_class=HTMLResponse)
        async def dashboard(request: Request):
            return self.templates.TemplateResponse("dashboard.css.html", {"request": request})
        
        @self.app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            await self.connect(websocket)
            try:
                while True:
                    # Keep connection alive and handle any incoming messages
                    data = await websocket.receive_text()
                    message = json.loads(data)
                    await self.handle_websocket_message(websocket, message)
            except WebSocketDisconnect:
                self.disconnect(websocket)
        
        @self.app.get("/api/analysis/{analysis_id}")
        async def get_analysis_data(analysis_id: str):
            return self.analysis_data.get(analysis_id, {})
        
        @self.app.get("/api/current")
        async def get_current_analysis():
            if self.current_analysis_id:
                return self.analysis_data.get(self.current_analysis_id, {})
            return {}
    
    async def connect(self, websocket: WebSocket):
        """Accept new WebSocket connection"""
        await websocket.accept()
        self.active_connections.append(websocket)
        
        # Send current analysis data if available
        if self.current_analysis_id and self.current_analysis_id in self.analysis_data:
            await websocket.send_text(json.dumps({
                "type": "full_update",
                "data": self.analysis_data[self.current_analysis_id]
            }))
    
    def disconnect(self, websocket: WebSocket):
        """Remove WebSocket connection"""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
    
    async def handle_websocket_message(self, websocket: WebSocket, message: Dict):
        """Handle incoming WebSocket messages"""
        msg_type = message.get("type")
        
        if msg_type == "ping":
            await websocket.send_text(json.dumps({"type": "pong"}))
        elif msg_type == "request_current":
            if self.current_analysis_id:
                data = self.analysis_data.get(self.current_analysis_id, {})
                await websocket.send_text(json.dumps({
                    "type": "full_update",
                    "data": data
                }))
    
    async def broadcast(self, message: Dict):
        """Broadcast message to all connected clients"""
        if self.active_connections:
            message_str = json.dumps(message)
            disconnected = []
            
            for connection in self.active_connections:
                try:
                    await connection.send_text(message_str)
                except Exception:
                    disconnected.append(connection)
            
            # Remove disconnected connections
            for conn in disconnected:
                self.disconnect(conn)
    
    def start_analysis(self, puzzle_path: str) -> str:
        """Start a new analysis session"""
        analysis_id = str(uuid.uuid4())[:8]
        self.current_analysis_id = analysis_id
        
        self.analysis_data[analysis_id] = {
            "id": analysis_id,
            "puzzle_path": puzzle_path,
            "start_time": datetime.now().isoformat(),
            "status": "starting",
            "phase": "initialization",
            "progress": 0,
            "insights": [],
            "transformations": [],
            "analyzers_run": [],
            "current_analyzer": None,
            "solution": None,
            "stats": {
                "total_insights": 0,
                "total_transformations": 0,
                "successful_analyzers": 0,
                "failed_analyzers": 0
            }
        }
        
        # Broadcast start
        asyncio.create_task(self.broadcast({
            "type": "analysis_started",
            "data": self.analysis_data[analysis_id]
        }))
        
        return analysis_id
    
    def update_phase(self, phase: str, progress: int = None):
        """Update the current analysis phase"""
        if not self.current_analysis_id:
            return
            
        data = self.analysis_data[self.current_analysis_id]
        data["phase"] = phase
        if progress is not None:
            data["progress"] = progress
        
        asyncio.create_task(self.broadcast({
            "type": "phase_update",
            "phase": phase,
            "progress": progress
        }))
    
    def start_analyzer(self, analyzer_name: str):
        """Mark an analyzer as starting"""
        if not self.current_analysis_id:
            return
            
        data = self.analysis_data[self.current_analysis_id]
        data["current_analyzer"] = analyzer_name
        data["status"] = "analyzing"
        
        asyncio.create_task(self.broadcast({
            "type": "analyzer_started",
            "analyzer": analyzer_name
        }))
    
    def finish_analyzer(self, analyzer_name: str, success: bool, insights_added: int = 0, transformations_added: int = 0):
        """Mark an analyzer as finished"""
        if not self.current_analysis_id:
            return
            
        data = self.analysis_data[self.current_analysis_id]
        data["current_analyzer"] = None
        
        analyzer_result = {
            "name": analyzer_name,
            "success": success,
            "timestamp": datetime.now().isoformat(),
            "insights_added": insights_added,
            "transformations_added": transformations_added
        }
        
        data["analyzers_run"].append(analyzer_result)
        
        if success:
            data["stats"]["successful_analyzers"] += 1
        else:
            data["stats"]["failed_analyzers"] += 1
        
        asyncio.create_task(self.broadcast({
            "type": "analyzer_finished",
            "analyzer": analyzer_name,
            "success": success,
            "result": analyzer_result
        }))
    
    def add_insight(self, text: str, analyzer: str):
        """Add a new insight"""
        if not self.current_analysis_id:
            return
            
        data = self.analysis_data[self.current_analysis_id]
        
        insight = {
            "text": text,
            "analyzer": analyzer,
            "timestamp": datetime.now().isoformat()
        }
        
        data["insights"].append(insight)
        data["stats"]["total_insights"] += 1
        
        asyncio.create_task(self.broadcast({
            "type": "new_insight",
            "insight": insight
        }))
    
    def add_transformation(self, name: str, description: str, analyzer: str, input_data: Any = None, output_data: Any = None):
        """Add a new transformation"""
        if not self.current_analysis_id:
            return
            
        data = self.analysis_data[self.current_analysis_id]
        
        transformation = {
            "name": name,
            "description": description,
            "analyzer": analyzer,
            "timestamp": datetime.now().isoformat(),
            "has_output": bool(output_data)
        }
        
        # Add preview of output if available
        if output_data:
            output_str = str(output_data)
            transformation["output_preview"] = output_str[:200] + ("..." if len(output_str) > 200 else "")
        
        data["transformations"].append(transformation)
        data["stats"]["total_transformations"] += 1
        
        asyncio.create_task(self.broadcast({
            "type": "new_transformation",
            "transformation": transformation
        }))
    
    def set_solution(self, solution: str):
        """Set the puzzle solution"""
        if not self.current_analysis_id:
            return
            
        data = self.analysis_data[self.current_analysis_id]
        data["solution"] = solution
        data["status"] = "completed"
        
        asyncio.create_task(self.broadcast({
            "type": "solution_found",
            "solution": solution
        }))
    
    def finish_analysis(self, success: bool = True):
        """Mark analysis as finished"""
        if not self.current_analysis_id:
            return
            
        data = self.analysis_data[self.current_analysis_id]
        data["status"] = "completed" if success else "failed"
        data["end_time"] = datetime.now().isoformat()
        data["progress"] = 100
        
        asyncio.create_task(self.broadcast({
            "type": "analysis_finished",
            "success": success,
            "final_data": data
        }))

# Global web UI manager instance
web_ui = WebUIManager()

class WebUIIntegration:
    """Integration class to connect Crypto Hunter with Web UI"""
    
    def __init__(self):
        self.server_thread = None
        self.server_running = False
    
    def start_server(self, host: str = "127.0.0.1", port: int = 8000):
        """Start the web server in a separate thread"""
        def run_server():
            uvicorn.run(web_ui.app, host=host, port=port, log_level="warning")
        
        if not self.server_running:
            self.server_thread = threading.Thread(target=run_server, daemon=True)
            self.server_thread.start()
            self.server_running = True
            
            print(f"🌐 Web UI available at: http://{host}:{port}")
            time.sleep(2)  # Give server time to start
    
    def integrate_with_logger(self):
        """Integrate with the solution logger for real-time updates"""
        
        def on_insight(text: str, analyzer: str, time_str: str = None):
            web_ui.add_insight(text, analyzer)
        
        def on_transformation(name: str, description: str, input_data: str, output_data: str, analyzer: str, time_str: str = None):
            web_ui.add_transformation(name, description, analyzer, input_data, output_data)
        
        def on_solution(solution: str):
            web_ui.set_solution(solution)
        
        # Register callbacks with solution logger
        solution_logger.register_llm_feedback_callback(
            lambda finding_type, analyzer, content: 
                on_insight(content, analyzer) if finding_type == 'insight' 
                else on_transformation(content, f"Transformation by {analyzer}", analyzer, None, None)
        )
    
    def start_analysis_session(self, puzzle_path: str) -> str:
        """Start a new analysis session"""
        return web_ui.start_analysis(puzzle_path)
    
    def update_analysis_phase(self, phase: str, progress: int = None):
        """Update the current analysis phase"""
        web_ui.update_phase(phase, progress)
    
    def start_analyzer(self, analyzer_name: str):
        """Notify that an analyzer is starting"""
        web_ui.start_analyzer(analyzer_name)
    
    def finish_analyzer(self, analyzer_name: str, success: bool, insights_added: int = 0, transformations_added: int = 0):
        """Notify that an analyzer has finished"""
        web_ui.finish_analyzer(analyzer_name, success, insights_added, transformations_added)
    
    def finish_analysis(self, success: bool = True):
        """Mark analysis as complete"""
        web_ui.finish_analysis(success)

# Global integration instance
web_integration = WebUIIntegration()
