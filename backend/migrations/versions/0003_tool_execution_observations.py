"""Persist normalized tool observations."""
from alembic import op
import sqlalchemy as sa

revision = "0003_tool_execution_observations"
down_revision = "0002_tool_execution_stderr"
branch_labels = None
depends_on = None


def upgrade():
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("tool_executions")}
    if "observations" not in columns:
        op.add_column("tool_executions", sa.Column("observations", sa.JSON(), nullable=True))


def downgrade():
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("tool_executions")}
    if "observations" in columns:
        op.drop_column("tool_executions", "observations")