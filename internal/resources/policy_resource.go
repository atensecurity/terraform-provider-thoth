package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/float64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/atensecurity/terraform-provider-thoth/internal/client"
	"github.com/atensecurity/terraform-provider-thoth/internal/tfhelpers"
)

var _ resource.Resource = &policyResource{}
var _ resource.ResourceWithImportState = &policyResource{}

// policyResource manages one policy rule in one environment. A rule created
// by a key that is not an org admin starts pending until an org admin
// approves it; Terraform reports that in status and does not approve it.
type policyResource struct {
	client   *client.Client
	tenantID string
}

type policyResourceModel struct {
	ID          types.String `tfsdk:"id"`
	PolicyID    types.String `tfsdk:"policy_id"`
	TenantID    types.String `tfsdk:"tenant_id"`
	Environment types.String `tfsdk:"environment"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Type        types.String `tfsdk:"type"`
	Enforcement types.String `tfsdk:"enforcement"`
	AppliedTo   types.List   `tfsdk:"applied_to"`
	RulesJSON   types.String `tfsdk:"rules_json"`
	// ArgumentConditions are numeric checks on the call's arguments, ANDed with
	// each other and with the rule's tool match. They are sent inside rules.
	ArgumentConditions types.List   `tfsdk:"argument_conditions"`
	Enabled            types.Bool   `tfsdk:"enabled"`
	Status             types.String `tfsdk:"status"`
	CreatedAt          types.String `tfsdk:"created_at"`
	UpdatedAt          types.String `tfsdk:"updated_at"`
}

func NewPolicyResource() resource.Resource {
	return &policyResource{}
}

func (r *policyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policy"
}

func (r *policyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a policy rule in one environment (dev or prod). A rule created with a key that is not an org admin's starts pending until an org admin approves it; status shows that.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "Resource ID: environment/policy_id.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"policy_id": schema.StringAttribute{
				Computed:      true,
				Description:   "Policy rule ID assigned by Thoth.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"tenant_id": schema.StringAttribute{Computed: true, Description: "Tenant ID from provider configuration."},
			"environment": schema.StringAttribute{
				Required:      true,
				Description:   "dev or prod. Changing it replaces the rule; promote a dev rule with the configuration preview or the API.",
				Validators:    []validator.String{stringvalidator.OneOf("dev", "prod")},
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"name":        schema.StringAttribute{Required: true, Description: "Rule name."},
			"description": schema.StringAttribute{Optional: true, Description: "Rule description."},
			"type": schema.StringAttribute{
				Required:    true,
				Description: "scope, budget, risk or data_access.",
				Validators:  []validator.String{stringvalidator.OneOf("scope", "budget", "risk", "data_access")},
			},
			"enforcement": schema.StringAttribute{
				Required:    true,
				Description: "monitor, review or block.",
				Validators:  []validator.String{stringvalidator.OneOf("monitor", "review", "block")},
			},
			"applied_to": schema.ListAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "Agent IDs the rule applies to, or [\"all\"] (the default).",
			},
			"rules_json": schema.StringAttribute{
				Optional:    true,
				Description: "What the rule matches, as a JSON object (for example with jsonencode()) with one of tool, tool_names, model_name, model_provider, purpose, data_classification, min_token_count or min_estimated_cost_usd, or the overlay keys blocked_tools and allowed_tools. A rule with none of these is refused, because Thoth would never apply it. Numeric checks on a tool's arguments go in argument_conditions (or, equally, under an argument_conditions key here; not both).",
			},
			"argument_conditions": schema.ListNestedAttribute{
				Optional: true,
				Description: "Numeric checks on the call's arguments, all of which must hold, together with the tool match in rules_json (tool or tool_names). " +
					"For example tool \"approve_expense\" with argument \"amount\", operator \"gt\" and value 100 matches approvals over 100. " +
					"At most 5. A review or block rule fails closed: a call that leaves the argument out matches (set when_missing to \"no_match\" to opt out), and a value that is present but not a plain number " +
					"(a string such as \"$150\" or \"1e3\", a boolean, a list), or a key that differs from the argument only in case or separators (Amount for amount), holds the call for review. " +
					"A plain decimal string such as \"150\" counts as a number. The rule depends on the exact argument name: use the name the tool declares, because synonyms such as amt are not recognised. " +
					"Matching is deterministic and reads only what the call sent; it cannot judge a value the client withheld, which holds the call for review instead.",
				Validators: []validator.List{listvalidator.SizeAtMost(5)},
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"argument": schema.StringAttribute{
						Required:    true,
						Description: "An argument name or a dotted path of at most 4 names (expense.amount). Names are letters, digits, _ and -, starting with a letter. Case matters.",
						Validators: []validator.String{
							stringvalidator.LengthAtMost(128),
							stringvalidator.RegexMatches(argumentPathPattern, "must be argument names of letters, digits, _ and -, starting with a letter, joined by dots, at most 4 levels"),
						},
					},
					"operator": schema.StringAttribute{
						Required:    true,
						Description: "gt, gte, lt, lte or eq.",
						Validators:  []validator.String{stringvalidator.OneOf("gt", "gte", "lt", "lte", "eq")},
					},
					"value": schema.Float64Attribute{
						Required:    true,
						Description: "The number to compare against: finite, between -1e15 and 1e15.",
						Validators:  []validator.Float64{float64validator.Between(-1e15, 1e15)},
					},
					"when_missing": schema.StringAttribute{
						Optional:    true,
						Description: "match or no_match: whether a call that leaves this argument out matches. Unset, a review or block rule matches it (fail closed) and a monitor rule does not. A present value that is not a plain number holds a review or block rule's call for review whatever this says.",
						Validators:  []validator.String{stringvalidator.OneOf("match", "no_match")},
					},
				}},
			},
			"enabled": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Default:     booldefault.StaticBool(true),
				Description: "Whether the rule applies. Turning a rule on needs an org admin's key; a pending rule stays pending until approved.",
			},
			"status":     schema.StringAttribute{Computed: true, Description: "pending, active, disabled or rejected."},
			"created_at": schema.StringAttribute{Computed: true, Description: "Creation timestamp."},
			"updated_at": schema.StringAttribute{Computed: true, Description: "Last update timestamp."},
		},
	}
}

func (r *policyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	data := tfhelpers.RequireResourceClient(req, resp)
	if data == nil {
		return
	}
	r.client = data.Client
	r.tenantID = data.TenantID
}

func (r *policyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan policyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	payload, err := policyPayload(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError("Invalid rules_json", err.Error())
		return
	}
	env := plan.Environment.ValueString()
	payload["environment"] = env
	created, err := r.client.CreatePolicy(ctx, env, payload)
	if err != nil {
		resp.Diagnostics.AddError("Error creating policy rule", err.Error())
		return
	}
	policyID := strings.TrimSpace(tfhelpers.GetString(created, "id"))
	if policyID == "" {
		resp.Diagnostics.AddError("Error creating policy rule", "GovAPI did not return the rule's id.")
		return
	}
	if !plan.Enabled.ValueBool() {
		if err := r.client.UpdatePolicy(ctx, policyID, env, map[string]any{"status": "disabled"}); err != nil {
			resp.Diagnostics.AddError("Error turning the new policy rule off", err.Error())
			return
		}
	}
	next, diags := r.readBack(ctx, policyID, env, plan)
	resp.Diagnostics.Append(diags...)
	if !diags.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
	}
}

func (r *policyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state policyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	policyID, env := strings.TrimSpace(state.PolicyID.ValueString()), state.Environment.ValueString()
	if policyID == "" {
		resp.State.RemoveResource(ctx)
		return
	}
	row, err := r.client.GetPolicy(ctx, policyID, env)
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Error reading policy rule", err.Error())
		return
	}
	next, diags := flattenPolicy(ctx, row, state, r.tenantID)
	resp.Diagnostics.Append(diags...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
}

func (r *policyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state policyResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	policyID, env := strings.TrimSpace(state.PolicyID.ValueString()), state.Environment.ValueString()
	payload, err := policyPayload(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError("Invalid rules_json", err.Error())
		return
	}
	// Only a change to enabled sends a status; a pending or rejected rule keeps its status.
	if !plan.Enabled.Equal(state.Enabled) {
		payload["status"] = map[bool]string{true: "active", false: "disabled"}[plan.Enabled.ValueBool()]
	}
	if err := r.client.UpdatePolicy(ctx, policyID, env, payload); err != nil {
		resp.Diagnostics.AddError("Error updating policy rule", err.Error())
		return
	}
	next, diags := r.readBack(ctx, policyID, env, plan)
	resp.Diagnostics.Append(diags...)
	if !diags.HasError() {
		resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
	}
}

func (r *policyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state policyResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	policyID := strings.TrimSpace(state.PolicyID.ValueString())
	if policyID == "" {
		return
	}
	if err := r.client.DeletePolicy(ctx, policyID, state.Environment.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Error deleting policy rule", err.Error())
	}
}

func (r *policyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	env, policyID, ok := strings.Cut(strings.TrimSpace(req.ID), "/")
	if !ok || (env != "dev" && env != "prod") || strings.TrimSpace(policyID) == "" {
		resp.Diagnostics.AddError("Invalid import ID", "Use environment/policy_id, for example prod/6ae1441907c1c31e7e44ca5a.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), env+"/"+policyID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("policy_id"), policyID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("environment"), env)...)
}

// readBack reads the rule after a change and flattens it onto the plan.
func (r *policyResource) readBack(ctx context.Context, policyID, env string, plan policyResourceModel) (policyResourceModel, diag.Diagnostics) {
	var diags diag.Diagnostics
	row, err := r.client.GetPolicy(ctx, policyID, env)
	if err != nil {
		diags.AddError("Error reading policy rule after change", err.Error())
		return plan, diags
	}
	return flattenPolicy(ctx, row, plan, r.tenantID)
}

// argumentPathPattern is up to four names of letters, digits, _ and -, joined
// by dots. GovAPI enforces the same shape and refuses the reserved names.
var argumentPathPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}(\.[A-Za-z][A-Za-z0-9_-]{0,63}){0,3}$`)

var argumentConditionAttrTypes = map[string]attr.Type{
	"argument": types.StringType, "operator": types.StringType, "value": types.Float64Type, "when_missing": types.StringType,
}

type argumentConditionModel struct {
	Argument    types.String  `tfsdk:"argument"`
	Operator    types.String  `tfsdk:"operator"`
	Value       types.Float64 `tfsdk:"value"`
	WhenMissing types.String  `tfsdk:"when_missing"`
}

// argumentConditionsPayload is the list as sent in rules.argument_conditions.
func argumentConditionsPayload(ctx context.Context, list types.List) ([]any, error) {
	var items []argumentConditionModel
	if diags := list.ElementsAs(ctx, &items, false); diags.HasError() {
		return nil, fmt.Errorf("argument_conditions: %v", diags)
	}
	out := make([]any, 0, len(items))
	for _, item := range items {
		entry := map[string]any{"argument": item.Argument.ValueString(), "operator": item.Operator.ValueString(), "value": item.Value.ValueFloat64()}
		if !item.WhenMissing.IsNull() && !item.WhenMissing.IsUnknown() {
			entry["when_missing"] = item.WhenMissing.ValueString()
		}
		out = append(out, entry)
	}
	return out, nil
}

// flattenArgumentConditions reads rules.argument_conditions back into the list.
func flattenArgumentConditions(raw any) (types.List, bool) {
	items, ok := raw.([]any)
	if !ok {
		return types.ListNull(types.ObjectType{AttrTypes: argumentConditionAttrTypes}), false
	}
	values := make([]attr.Value, 0, len(items))
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		whenMissing := types.StringNull()
		if text, ok := entry["when_missing"].(string); ok && (text == "match" || text == "no_match") {
			whenMissing = types.StringValue(text)
		}
		number, _ := entry["value"].(float64)
		values = append(values, types.ObjectValueMust(argumentConditionAttrTypes, map[string]attr.Value{
			"argument":     types.StringValue(fmt.Sprint(entry["argument"])),
			"operator":     types.StringValue(fmt.Sprint(entry["operator"])),
			"value":        types.Float64Value(number),
			"when_missing": whenMissing,
		}))
	}
	return types.ListValueMust(types.ObjectType{AttrTypes: argumentConditionAttrTypes}, values), true
}

// policyPayload is the route body: the fields a person edits.
func policyPayload(ctx context.Context, plan policyResourceModel) (map[string]any, error) {
	payload := map[string]any{
		"name":        strings.TrimSpace(plan.Name.ValueString()),
		"type":        plan.Type.ValueString(),
		"enforcement": plan.Enforcement.ValueString(),
	}
	if !plan.Description.IsNull() && !plan.Description.IsUnknown() {
		payload["description"] = strings.TrimSpace(plan.Description.ValueString())
	}
	if !plan.AppliedTo.IsNull() && !plan.AppliedTo.IsUnknown() {
		var applied []string
		_ = plan.AppliedTo.ElementsAs(ctx, &applied, false)
		payload["applied_to"] = applied
	}
	if !plan.RulesJSON.IsNull() && !plan.RulesJSON.IsUnknown() && strings.TrimSpace(plan.RulesJSON.ValueString()) != "" {
		var rules map[string]any
		if err := json.Unmarshal([]byte(plan.RulesJSON.ValueString()), &rules); err != nil || rules == nil {
			return nil, fmt.Errorf("rules_json must be a JSON object: %v", err)
		}
		payload["rules"] = rules
	}
	if !plan.ArgumentConditions.IsNull() && !plan.ArgumentConditions.IsUnknown() {
		rules, _ := payload["rules"].(map[string]any)
		if rules == nil {
			rules = map[string]any{}
		}
		if _, dup := rules["argument_conditions"]; dup {
			return nil, fmt.Errorf("argument_conditions is set here and inside rules_json; set it in one place")
		}
		conditions, err := argumentConditionsPayload(ctx, plan.ArgumentConditions)
		if err != nil {
			return nil, err
		}
		rules["argument_conditions"] = conditions
		payload["rules"] = rules
	}
	return payload, nil
}

// canonicalJSON compacts a JSON object with sorted keys, or returns "".
func canonicalJSON(raw string) string {
	var value any
	if json.Unmarshal([]byte(raw), &value) != nil {
		return ""
	}
	data, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(data)
}

func flattenPolicy(ctx context.Context, row map[string]any, current policyResourceModel, tenantID string) (policyResourceModel, diag.Diagnostics) {
	next := current
	policyID := strings.TrimSpace(tfhelpers.GetString(row, "id"))
	env := strings.TrimSpace(tfhelpers.GetString(row, "environment"))
	if env == "" {
		env = current.Environment.ValueString()
	}
	next.ID = types.StringValue(env + "/" + policyID)
	next.PolicyID = types.StringValue(policyID)
	next.TenantID = types.StringValue(tenantID)
	next.Environment = types.StringValue(env)
	next.Name = types.StringValue(tfhelpers.GetString(row, "name"))
	if description := nullableString(row, "description"); !description.IsNull() || !current.Description.IsNull() {
		next.Description = description
	}
	next.Type = types.StringValue(tfhelpers.GetString(row, "type"))
	next.Enforcement = types.StringValue(tfhelpers.GetString(row, "enforcement"))
	status := tfhelpers.GetString(row, "status")
	next.Status = types.StringValue(status)
	next.Enabled = types.BoolValue(status != "disabled")
	next.CreatedAt = nullableString(row, "created_at")
	next.UpdatedAt = nullableString(row, "updated_at")

	applied := []attr.Value{}
	if raw, ok := row["applied_to"].([]any); ok {
		for _, v := range raw {
			if s, ok := v.(string); ok {
				applied = append(applied, types.StringValue(s))
			}
		}
	}
	list, diags := types.ListValue(types.StringType, applied)
	next.AppliedTo = list

	// Keep the configured text when it means the same rules, so formatting never shows as drift.
	// A rule configured with the typed argument_conditions block has them read back into it, and
	// compared without them against rules_json; one configured inside rules_json keeps them there.
	if rules, ok := row["rules"]; ok && rules != nil {
		serverRules, _ := rules.(map[string]any)
		typed := !current.ArgumentConditions.IsNull() && !current.ArgumentConditions.IsUnknown()
		if typed && serverRules != nil {
			rest := make(map[string]any, len(serverRules))
			for key, value := range serverRules {
				rest[key] = value
			}
			conditions, found := flattenArgumentConditions(rest["argument_conditions"])
			delete(rest, "argument_conditions")
			if found {
				next.ArgumentConditions = conditions
			} else {
				next.ArgumentConditions = types.ListNull(types.ObjectType{AttrTypes: argumentConditionAttrTypes})
			}
			rules = rest
		} else if current.ArgumentConditions.IsUnknown() {
			next.ArgumentConditions = types.ListNull(types.ObjectType{AttrTypes: argumentConditionAttrTypes})
		}
		data, _ := json.Marshal(rules)
		server := canonicalJSON(string(data))
		if server == "{}" && current.RulesJSON.IsNull() {
			next.RulesJSON = types.StringNull()
		} else if current.RulesJSON.IsNull() || canonicalJSON(current.RulesJSON.ValueString()) != server {
			next.RulesJSON = types.StringValue(server)
		}
	} else {
		if !current.RulesJSON.IsNull() {
			next.RulesJSON = types.StringNull()
		}
		if !current.ArgumentConditions.IsNull() {
			next.ArgumentConditions = types.ListNull(types.ObjectType{AttrTypes: argumentConditionAttrTypes})
		}
	}
	return next, diags
}
