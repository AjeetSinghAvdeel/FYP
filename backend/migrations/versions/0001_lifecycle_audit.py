"""Add persisted lifecycle, execution, finding, and audit data."""
from alembic import op
import sqlalchemy as sa

revision = "0001_lifecycle_audit"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("assessments"):
        from app.core.database import Base
        import app.models

        Base.metadata.create_all(bind=bind)
        return
    user_columns = {column["name"] for column in inspector.get_columns("users")}
    if "role" not in user_columns:
        op.add_column("users", sa.Column("role", sa.String(30), nullable=True, server_default="security_operator"))
    columns = {column["name"] for column in inspector.get_columns("assessments")}
    additions = [
        ("current_phase", sa.String(40), "draft"),
        ("progress", sa.Integer(), 0),
        ("requests_used", sa.Integer(), 0),
        ("job_id", sa.String(80), None),
        ("last_error", sa.Text(), None),
        ("started_at", sa.DateTime(), None),
        ("completed_at", sa.DateTime(), None),
    ]
    for name, type_, default in additions:
        if name not in columns:
            op.add_column("assessments", sa.Column(name, type_, nullable=True, default=default))
    finding_columns = {column["name"] for column in inspector.get_columns("findings")}
    for name, type_, default in [("risk_score", sa.Float(), 0.0), ("risk_breakdown", sa.JSON(), None), ("simulated", sa.Boolean(), False)]:
        if name not in finding_columns:
            op.add_column("findings", sa.Column(name, type_, nullable=True, default=default))
    op.create_table("tool_executions", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("assessment_id", sa.Integer(), sa.ForeignKey("assessments.id"), nullable=False), sa.Column("tool", sa.String(40), nullable=False), sa.Column("status", sa.String(30), nullable=False), sa.Column("mode", sa.String(20), nullable=False), sa.Column("target", sa.String(255), nullable=False), sa.Column("return_code", sa.Integer()), sa.Column("output", sa.Text()), sa.Column("duration_ms", sa.Integer()), sa.Column("started_at", sa.DateTime(), nullable=False), sa.Column("finished_at", sa.DateTime()))
    op.create_table("audit_events", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id")), sa.Column("assessment_id", sa.Integer(), sa.ForeignKey("assessments.id")), sa.Column("event_type", sa.String(60), nullable=False), sa.Column("action", sa.String(120)), sa.Column("decision", sa.String(40)), sa.Column("outcome", sa.Text()), sa.Column("evidence_reference", sa.Text()), sa.Column("previous_state", sa.JSON()), sa.Column("current_state", sa.JSON()), sa.Column("previous_hash", sa.String(64)), sa.Column("event_hash", sa.String(64), nullable=False, unique=True), sa.Column("created_at", sa.DateTime(), nullable=False))
    op.create_table("evaluation_runs", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("owner_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False), sa.Column("scenario", sa.String(120), nullable=False), sa.Column("configuration", sa.String(20), nullable=False), sa.Column("seed", sa.Integer()), sa.Column("parameters", sa.JSON()), sa.Column("created_at", sa.DateTime(), nullable=False))
    op.create_table("evaluation_results", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("run_id", sa.Integer(), sa.ForeignKey("evaluation_runs.id"), nullable=False), sa.Column("metric", sa.String(60), nullable=False), sa.Column("value", sa.Float(), nullable=False), sa.Column("details", sa.JSON()))


def downgrade():
    bind = op.get_bind()
    indexes = {index["name"] for index in sa.inspect(bind).get_indexes("assessments")}
    if "ix_assessments_job_id" in indexes:
        op.drop_index("ix_assessments_job_id", table_name="assessments")
    op.drop_table("audit_events")
    op.drop_table("tool_executions")
    op.drop_table("evaluation_results")
    op.drop_table("evaluation_runs")
    for name in ["simulated", "risk_breakdown", "risk_score"]:
        op.drop_column("findings", name)
    for name in ["completed_at", "started_at", "last_error", "job_id", "requests_used", "progress", "current_phase"]:
        op.drop_column("assessments", name)
    if "role" in {column["name"] for column in sa.inspect(bind).get_columns("users")}:
        op.drop_column("users", "role")
