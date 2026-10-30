"""Preserve stderr and request-budget metadata for tool executions."""
from alembic import op
import sqlalchemy as sa

revision = "0002_tool_execution_stderr"
down_revision = "0001_lifecycle_audit"
branch_labels = None
depends_on = None


def upgrade():
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("tool_executions")}
    if "stderr" not in columns:
        op.add_column("tool_executions", sa.Column("stderr", sa.Text(), nullable=True))
    if "request_budget" not in columns:
        op.add_column("tool_executions", sa.Column("request_budget", sa.Integer(), nullable=True))


def downgrade():
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("tool_executions")}
    if "request_budget" in columns:
        op.drop_column("tool_executions", "request_budget")
    if "stderr" in columns:
        op.drop_column("tool_executions", "stderr")
