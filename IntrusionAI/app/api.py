"""
FastAPI REST API layer for IntrusionAI Hybrid UEBA System
Wraps the orchestrator with proper HTTP endpoints, validation, and documentation
"""

from fastapi import FastAPI, HTTPException, Query, BackgroundTasks, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from enum import Enum
import logging
from contextlib import asynccontextmanager
import json
from app.audit_logger import AuditLogger, AuditAction
from app.orchestrator import IntrusionAIOrchestrator


# ==================== Logging Setup ====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ==================== Pydantic Models ====================

class RiskLevelEnum(str, Enum):
    """Risk level enumeration"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    MINIMAL = "MINIMAL"


class EventMetadata(BaseModel):
    """Metadata for user events"""
    source: str = Field(..., description="Event source (e.g., 'endpoint', 'network')")
    timestamp: Optional[datetime] = Field(default_factory=datetime.now)
    device_type: str = Field(default="windows", description="Device type")
    location: Optional[str] = Field(None, description="Geographic location")
    network_segment: Optional[str] = Field(None, description="Network segment")


class EventRequest(BaseModel):
    """Request model for user event processing"""
    user_id: str = Field(..., description="Unique user identifier")
    device_id: str = Field(..., description="Unique device identifier")
    features: Dict[str, float] = Field(..., description="Feature vector for ML analysis")
    metadata: Optional[EventMetadata] = None

    @validator('user_id', 'device_id')
    def validate_ids(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError("ID cannot be empty")
        return v.strip()

    @validator('features')
    def validate_features(cls, v):
        if not v or len(v) == 0:
            raise ValueError("Features cannot be empty")
        return v


class EventResponse(BaseModel):
    """Response model for event processing"""
    event_id: str = Field(..., description="Unique event ID")
    user_id: str
    device_id: str
    risk_score: float = Field(..., ge=0, le=1)
    risk_level: RiskLevelEnum
    timestamp: datetime
    findings: List[str] = Field(default_factory=list)
    actions: List[Dict[str, Any]] = Field(default_factory=list)
    component_scores: Dict[str, float]
    requires_investigation: bool


class UserRiskProfileResponse(BaseModel):
    """User risk profile response"""
    user_id: str
    current_risk_score: float = Field(..., ge=0, le=1)
    risk_level: RiskLevelEnum
    trust_score: float = Field(..., ge=0, le=1)
    risk_trend: str = Field(..., description="INCREASING, STABLE, or DECREASING")
    anomaly_count_7d: int = Field(..., description="Anomalies in last 7 days")
    alert_count_7d: int = Field(..., description="Alerts in last 7 days")
    last_alert_time: Optional[datetime]
    peer_deviation: float = Field(default=0.0, ge=0, le=1)
    
    class Config:
        schema_extra = {
            "example": {
                "user_id": "user123",
                "current_risk_score": 0.65,
                "risk_level": "HIGH",
                "trust_score": 0.42,
                "risk_trend": "INCREASING",
                "anomaly_count_7d": 8,
                "alert_count_7d": 3,
                "last_alert_time": "2024-01-15T10:30:00"
            }
        }


class UserDashboardResponse(BaseModel):
    """Comprehensive user dashboard"""
    user_id: str
    risk_profile: UserRiskProfileResponse
    recent_events: List[Dict[str, Any]] = Field(default_factory=list)
    active_violations: List[Dict[str, Any]] = Field(default_factory=list)
    network_anomalies: List[Dict[str, Any]] = Field(default_factory=list)
    dlp_violations: List[Dict[str, Any]] = Field(default_factory=list)
    peer_group_summary: Dict[str, Any] = Field(default_factory=dict)
    recommended_actions: List[str] = Field(default_factory=list)


class OrganizationSummaryResponse(BaseModel):
    """Organization-wide summary"""
    total_users_monitored: int
    high_risk_users_count: int
    critical_alerts_24h: int
    total_anomalies_24h: int
    active_incidents: int
    dlp_violations_24h: int
    top_risk_users: List[Dict[str, Any]] = Field(default_factory=list)
    threat_intel_hits: int
    network_anomalies_24h: int
    honeypot_interactions_24h: int
    last_updated: datetime = Field(default_factory=datetime.now)


class AuditLogRequest(BaseModel):
    """Audit log entry request"""
    user_id: str = Field(..., description="User who performed action")
    action: str = Field(..., description="Action performed")
    resource: Optional[str] = Field(None, description="Resource affected")
    severity: str = Field(default="INFO", description="Severity level")
    details: Optional[Dict[str, Any]] = None
    timestamp: Optional[datetime] = Field(default_factory=datetime.now)


class AuditLogResponse(BaseModel):
    """Audit log entry response"""
    log_id: str
    user_id: str
    action: str
    resource: Optional[str]
    severity: str
    details: Optional[Dict[str, Any]]
    timestamp: datetime
    status: str = "logged"


class HealthCheckResponse(BaseModel):
    """System health status"""
    status: str = Field(..., description="Overall system status")
    timestamp: datetime
    modules: Dict[str, Any] = Field(default_factory=dict)
    database_connected: bool = False
    redis_connected: bool = False
    uptime_seconds: int = 0


# ==================== API Initialization & Lifespan ====================

orchestrator = None
api_start_time = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown events"""
    global orchestrator, api_start_time
    
    # Startup
    try:
        logger.info("Initializing IntrusionAI Orchestrator...")
        orchestrator = IntrusionAIOrchestrator()
        api_start_time = datetime.now()
        logger.info("Orchestrator initialized successfully")
        
        # Perform health check
        health_check = orchestrator.health_check()
        logger.info(f"Health check result: {health_check}")
    except Exception as e:
        logger.error(f"Failed to initialize orchestrator: {str(e)}", exc_info=True)
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down IntrusionAI API...")
    # Cleanup operations here if needed
    logger.info("Shutdown complete")


# Initialize FastAPI app
app = FastAPI(
    title="IntrusionAI Hybrid UEBA System",
    description="Enterprise UEBA and behavioral intelligence API",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)


# ==================== Helper Functions ====================

def get_orchestrator() -> IntrusionAIOrchestrator:
    """Dependency to get orchestrator instance"""
    if orchestrator is None:
        raise HTTPException(
            status_code=503,
            detail="Service not initialized. Please try again later."
        )
    return orchestrator


def generate_event_id() -> str:
    """Generate unique event ID"""
    import uuid
    return str(uuid.uuid4())


def map_risk_level(risk_level: str) -> RiskLevelEnum:
    """Map internal risk level to enum"""
    risk_map = {
        "CRITICAL": RiskLevelEnum.CRITICAL,
        "HIGH": RiskLevelEnum.HIGH,
        "MEDIUM": RiskLevelEnum.MEDIUM,
        "LOW": RiskLevelEnum.LOW,
        "MINIMAL": RiskLevelEnum.MINIMAL
    }
    return risk_map.get(risk_level, RiskLevelEnum.MINIMAL)


# ==================== Event Processing Endpoints ====================

@app.post(
    "/api/v1/events",
    response_model=EventResponse,
    summary="Process User Event",
    tags=["Events"]
)
async def process_event(
    event: EventRequest,
    orchestrator_instance: IntrusionAIOrchestrator = Depends(get_orchestrator)
) -> EventResponse:
    """
    Process a user event through the full UEBA pipeline.
    
    This endpoint:
    1. Receives user event with features
    2. Runs ML anomaly detection
    3. Performs threat intelligence lookup
    4. Compares against peer groups
    5. Correlates multi-source events
    6. Checks network/DLP violations
    7. Detects honeypot interactions
    8. Calculates unified risk score
    9. Executes automated response if needed
    10. Logs all findings and actions
    
    Returns comprehensive threat analysis and recommended actions.
    """
    try:
        logger.info(f"Processing event for user {event.user_id} on device {event.device_id}")
        
        # Get metadata
        metadata = event.metadata.dict() if event.metadata else {}
        
        # Process through orchestrator
        result = orchestrator_instance.process_user_event(
            user_id=event.user_id,
            device_id=event.device_id,
            features=event.features,
            metadata=metadata
        )
        
        # Map response
        event_id = generate_event_id()
        response = EventResponse(
            event_id=event_id,
            user_id=event.user_id,
            device_id=event.device_id,
            risk_score=float(result.get('risk_score', 0.0)),
            risk_level=map_risk_level(result.get('risk_level', 'MINIMAL')),
            timestamp=datetime.now(),
            findings=result.get('findings', []),
            actions=result.get('actions', []),
            component_scores=result.get('component_scores', {}),
            requires_investigation=float(result.get('risk_score', 0.0)) >= 0.7
        )
        
        logger.info(f"Event {event_id} processed: risk_level={response.risk_level}, "
                   f"risk_score={response.risk_score:.3f}")
        
        return response
        
    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error processing event: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error during event processing")


# ==================== User Risk Endpoints ====================

@app.get(
    "/api/v1/users/{user_id}/risk-score",
    response_model=UserRiskProfileResponse,
    summary="Get User Risk Score",
    tags=["Users"]
)
async def get_user_risk_score(
    user_id: str,
    orchestrator_instance: IntrusionAIOrchestrator = Depends(get_orchestrator)
) -> UserRiskProfileResponse:
    """
    Get current risk profile for a specific user.
    
    Returns:
    - Current risk score (0-1)
    - Risk level (CRITICAL, HIGH, MEDIUM, LOW, MINIMAL)
    - Trust score based on historical behavior
    - Risk trend (INCREASING, STABLE, DECREASING)
    - 7-day anomaly and alert counts
    - Peer group deviation score
    """
    try:
        logger.info(f"Retrieving risk profile for user {user_id}")
        
        # Get user profile from risk profiler
        user_profile = orchestrator_instance.risk_profiler.get_user_profile(user_id)
        
        if user_profile is None:
            logger.warning(f"No risk profile found for user {user_id}")
            raise HTTPException(status_code=404, detail=f"User {user_id} not found")
        
        # Calculate metrics
        risk_score = orchestrator_instance.risk_profiler.engine.calculate_risk(user_id)
        trust_score = orchestrator_instance.risk_profiler._calculate_trust_score(user_profile)
        
        # Determine risk level
        if risk_score >= 0.85:
            risk_level = RiskLevelEnum.CRITICAL
        elif risk_score >= 0.70:
            risk_level = RiskLevelEnum.HIGH
        elif risk_score >= 0.50:
            risk_level = RiskLevelEnum.MEDIUM
        elif risk_score >= 0.25:
            risk_level = RiskLevelEnum.LOW
        else:
            risk_level = RiskLevelEnum.MINIMAL
        
        response = UserRiskProfileResponse(
            user_id=user_id,
            current_risk_score=risk_score,
            risk_level=risk_level,
            trust_score=trust_score,
            risk_trend=user_profile.risk_trend,
            anomaly_count_7d=len(user_profile.anomaly_scores[-7:]) if user_profile.anomaly_scores else 0,
            alert_count_7d=len(user_profile.alert_history[-7:]) if user_profile.alert_history else 0,
            last_alert_time=user_profile.alert_history[-1] if user_profile.alert_history else None,
            peer_deviation=0.0  # Will be updated with peer group analysis
        )
        
        logger.info(f"Risk profile retrieved for {user_id}: {risk_level}")
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving risk score for {user_id}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Error retrieving risk score")


@app.get(
    "/api/v1/users/{user_id}/dashboard",
    response_model=UserDashboardResponse,
    summary="Get User Dashboard",
    tags=["Users"]
)
async def get_user_dashboard(
    user_id: str,
    days: int = Query(7, ge=1, le=90, description="Days of history to include"),
    orchestrator_instance: IntrusionAIOrchestrator = Depends(get_orchestrator)
) -> UserDashboardResponse:
    """
    Get comprehensive user dashboard with all relevant security information.
    
    Includes:
    - User risk profile
    - Recent suspicious events
    - Active policy violations
    - Network anomalies
    - DLP violations
    - Peer group comparison
    - Recommended security actions
    """
    try:
        logger.info(f"Generating dashboard for user {user_id}")
        
        # Get dashboard from orchestrator
        dashboard = orchestrator_instance.get_user_dashboard(user_id)
        
        # Get risk profile
        risk_profile_result = await get_user_risk_score(user_id, orchestrator_instance)
        
        response = UserDashboardResponse(
        user_id=user_id,
        risk_profile=risk_profile_result,
        recent_events=dashboard.get('timeline', []),
        active_violations=[],
        network_anomalies=[],
        dlp_violations=[{'count': dashboard.get('dlp_violations', 0)}],
        peer_group_summary={},
        recommended_actions=[])

        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating dashboard for {user_id}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Error generating dashboard")


# ==================== Organization-Wide Endpoints ====================

@app.get(
    "/api/v1/organization/summary",
    response_model=OrganizationSummaryResponse,
    summary="Get Organization Summary",
    tags=["Organization"]
)
async def get_organization_summary(
    orchestrator_instance: IntrusionAIOrchestrator = Depends(get_orchestrator)
) -> OrganizationSummaryResponse:
    """
    Get organization-wide security summary and KPIs.
    
    Returns:
    - Total monitored users
    - High-risk user count
    - Critical alerts in last 24h
    - Total anomalies detected
    - Active incidents
    - DLP violations
    - Top at-risk users
    - Threat intelligence hits
    - Network anomalies
    - Honeypot interactions
    """
    try:
        logger.info("Retrieving organization summary")
        
        # Get summary from orchestrator
        summary = orchestrator_instance.get_organization_summary()
        
        response = OrganizationSummaryResponse(
        total_users_monitored=len(summary.get('high_risk_users', [])),
        high_risk_users_count=len(summary.get('high_risk_users', [])),
        critical_alerts_24h=summary.get('audit_stats', {}).get('total_logs', 0),
        total_anomalies_24h=0,
        active_incidents=0,
        dlp_violations_24h=0,
        top_risk_users=summary.get('high_risk_users', []),
        threat_intel_hits=summary.get('threat_intel_stats', {}).get('total_lookups', 0),
        network_anomalies_24h=0,
        honeypot_interactions_24h=summary.get('honeypot_summary', {}).get('total_interactions', 0)
)
        
        return response
        
    except Exception as e:
        logger.error(f"Error retrieving organization summary: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Error retrieving organization summary")


# ==================== Audit & Compliance Endpoints ====================

@app.post(
    "/api/v1/audit-logs",
    response_model=AuditLogResponse,
    summary="Log Audit Event",
    tags=["Audit"]
)
async def log_audit_event(
    audit_log: AuditLogRequest,
    orchestrator_instance: IntrusionAIOrchestrator = Depends(get_orchestrator)
) -> AuditLogResponse:
    """
    Log an audit event for compliance purposes.
    
    Captures:
    - User actions
    - Resource modifications
    - Security events
    - Policy violations
    - Administrative changes
    
    All logs are encrypted and stored for compliance reporting.
    """
    try:
        logger.info(f"Logging audit event: {audit_log.action} by {audit_log.user_id}")
        
        # Log through audit logger
        # Log through audit logger
        try:
            audit_action = AuditAction(audit_log.action.lower())
        except ValueError:
            audit_action = AuditAction.DATA_ACCESSED  # fallback default

        orchestrator_instance.audit_logger.log(
            action=audit_action,
            user_id=audit_log.user_id,
            resource_type=audit_log.resource,
            details=audit_log.details or {}
        )
        
        log_id = generate_event_id()
        response = AuditLogResponse(
            log_id=log_id,
            user_id=audit_log.user_id,
            action=audit_log.action,
            resource=audit_log.resource,
            severity=audit_log.severity,
            details=audit_log.details,
            timestamp=audit_log.timestamp
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Error logging audit event: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Error logging audit event")


@app.get(
    "/api/v1/audit-logs",
    summary="Search Audit Logs",
    tags=["Audit"]
)
async def search_audit_logs(
    user_id: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    start_time: Optional[datetime] = Query(None),
    end_time: Optional[datetime] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    orchestrator_instance: IntrusionAIOrchestrator = Depends(get_orchestrator)
) -> List[Dict[str, Any]]:
    """
    Search audit logs with filtering.
    
    Parameters:
    - user_id: Filter by user
    - action: Filter by action type
    - start_time: Start of time range
    - end_time: End of time range
    - limit: Maximum results (default 100)
    
    Returns audit log entries matching criteria.
    """
    try:
        logger.info(f"Searching audit logs: user={user_id}, action={action}")
        
        # Search through audit logger
        audit_action_filter = None
        if action:
            try:
                audit_action_filter = AuditAction(action.lower())
            except ValueError:
                pass

        results = orchestrator_instance.audit_logger.search(
            user_id=user_id,
            action=audit_action_filter,
            start_time=start_time,
            end_time=end_time
        )
        
        # Convert to dict and limit
        return [log.__dict__ for log in results][:limit]
        
    except Exception as e:
        logger.error(f"Error searching audit logs: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Error searching audit logs")


# ==================== Health & Monitoring Endpoints ====================

@app.get(
    "/api/v1/health",
    response_model=HealthCheckResponse,
    summary="System Health Check",
    tags=["System"]
)
async def health_check(
    orchestrator_instance: IntrusionAIOrchestrator = Depends(get_orchestrator)
) -> HealthCheckResponse:
    """
    Get system health status and module availability.
    
    Returns:
    - Overall system status (healthy/degraded/critical)
    - Individual module status
    - Database connectivity
    - Cache connectivity
    - System uptime
    """
    try:
        # Get health from orchestrator
        health = orchestrator_instance.health_check()
        
        # Calculate uptime
        uptime = (datetime.now() - api_start_time).total_seconds() if api_start_time else 0
        
        response = HealthCheckResponse(
            status=health.get('status', 'unknown'),
            timestamp=datetime.now(),
            modules=health.get('modules', {}),
            uptime_seconds=int(uptime)
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Error in health check: {str(e)}", exc_info=True)
        return HealthCheckResponse(
            status="critical",
            timestamp=datetime.now(),
            modules={},
            uptime_seconds=0
        )


@app.get(
    "/api/v1/status",
    summary="Quick Status Check",
    tags=["System"]
)
async def status_check() -> Dict[str, Any]:
    """Quick status check - lightweight endpoint for load balancers"""
    return {
        "status": "ok" if orchestrator is not None else "initializing",
        "timestamp": datetime.now().isoformat(),
        "api_version": "1.0.0"
    }


# ==================== Root Endpoint ====================

@app.get("/", include_in_schema=False)
async def root():
    """Root endpoint redirects to API documentation"""
    return {
        "message": "IntrusionAI Hybrid UEBA System",
        "documentation": "/docs",
        "api_version": "1.0.0",
        "status": "operational" if orchestrator is not None else "initializing"
    }


# ==================== Error Handlers ====================

@app.exception_handler(ValueError)
async def value_error_handler(request, exc):
    """Handle validation errors"""
    logger.error(f"Validation error: {str(exc)}")
    return JSONResponse(
        status_code=400,
        content={"detail": str(exc), "error_type": "ValidationError"}
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Handle unexpected errors"""
    logger.error(f"Unexpected error: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "detail": "An unexpected error occurred",
            "error_type": type(exc).__name__
        }
    )


# ==================== Startup/Shutdown Messages ====================

if __name__ == "__main__":
    import uvicorn
    
    logger.info("Starting IntrusionAI API server...")
    logger.info("Documentation available at http://localhost:8000/docs")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
        access_log=True,
        reload=False  # Set to True for development
    )
