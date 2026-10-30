from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user_model
from app.core.database import get_db
from app.models import EvaluationResult, EvaluationRun
from app.schemas.evaluation import EvaluationExecutionRequest, EvaluationRequest
from app.services.evaluation import CONFIGURATIONS, calculate_metrics, run_ablation
from app.services.lab import execute_configuration

router = APIRouter(prefix="/api/evaluations", tags=["evaluations"])


@router.post("/run")
def run_evaluation(payload: EvaluationRequest, current_user: object = Depends(get_current_user_model), db: Session = Depends(get_db)) -> dict:
    metrics = calculate_metrics(payload.ground_truth, payload.observed)
    run = EvaluationRun(owner_id=current_user.id, scenario=payload.scenario, configuration=CONFIGURATIONS[payload.configuration]["name"], seed=payload.seed, parameters={"configuration": payload.configuration})
    db.add(run)
    db.flush()
    for metric, result in metrics.items():
        db.add(EvaluationResult(run_id=run.id, metric=metric, value=result["value"], details=result["details"]))
    db.commit()
    return {"run_id": run.id, "scenario": payload.scenario, "configuration": payload.configuration, "metrics": metrics, "ablations": run_ablation(payload.ground_truth, payload.observed, payload.ablations)}


@router.get("")
def list_evaluations(current_user: object = Depends(get_current_user_model), db: Session = Depends(get_db)) -> list[dict]:
    runs = db.query(EvaluationRun).filter(EvaluationRun.owner_id == current_user.id).order_by(EvaluationRun.created_at.desc()).all()
    return [{"id": run.id, "scenario": run.scenario, "configuration": run.configuration, "seed": run.seed, "created_at": run.created_at, "metrics": {result.metric: result.value for result in run.results}} for run in runs]


@router.post("/execute")
def execute_evaluation(payload: EvaluationExecutionRequest, current_user: object = Depends(get_current_user_model), db: Session = Depends(get_db)) -> dict:
    result = execute_configuration(payload.target_url, payload.allowed_tools, payload.target_scope, payload.ground_truth, payload.configuration, payload.mode, payload.budget)
    run = EvaluationRun(
        owner_id=current_user.id,
        scenario=payload.scenario,
        configuration=result["configuration_name"],
        parameters={"target_url": payload.target_url, "mode": payload.mode, "budget": payload.budget, "observed": result["observed"]},
    )
    db.add(run)
    db.flush()
    for metric, metric_result in result["metrics"].items():
        db.add(EvaluationResult(run_id=run.id, metric=metric, value=metric_result["value"], details=metric_result["details"]))
    db.commit()
    result["run_id"] = run.id
    return result