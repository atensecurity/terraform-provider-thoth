resource "thoth_tool_classification" "read_orders" {
  tool_name = "orders.list"
  classes   = ["read"]
}

resource "thoth_tool_classification" "delete_order" {
  tool_name = "orders.delete"
  classes   = ["delete"]
}
