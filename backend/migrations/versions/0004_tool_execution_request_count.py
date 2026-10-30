"""Record observed request counts independently of configured budgets."""
from alembic import op
import sqlalchemy as sa

revision = "0004_tool_execution_request_count"
down_revision = "0003_tool_execution_observations"
branch_labels = None
depends_on = None


def upgrade():
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("tool_executions")}
    if "requests_made" not in columns:
        op.add_column("tool_executions", sa.Column("requests_made", sa.Integer(), nullable=True))


def downgrade():
    columns = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("tool_executions")}
    if "requests_made" in columns:
        op.drop_column("tool_executions", "requests_made")