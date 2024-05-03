from importlib import import_module  # For dynamic rule loading
from flask import Flask, request, jsonify

app = Flask(__name__)

def block_attack(data, rule_set):
  """
  Checks request data against a set of WAF rules.

  Args:
      data (str): The request data to be checked.
      rule_set (list): A list of dictionaries containing WAF rule information (id, pattern).

  Returns:
      bool: True if an attack is detected, False otherwise.
  """

  for rule in rule_set:
    if re.search(rule["pattern"], data):
      return True, rule["id"]  # Return both attack flag and rule ID for logging
  return False, None


@app.route("/", methods=["POST"])
def protect():
  data = request.get_json()
  if data is None:
    return jsonify({"error": "Invalid request format"}), 400

  # Load WAF rules from configuration file
  rule_module = import_module("waf_rules")  # Assuming waf_rules.py in same directory
  rule_set = rule_module.rules

  # Check for attacks using the improved function
  is_attack, rule_id = block_attack(data.get("username", ""), rule_set)
  if is_attack:
    return jsonify({"error": f"Potential {rule_id} attack attempted"}), 403

  # Process the request if it passes the checks (replace with actual logic)
  return jsonify({"message": "Request processed successfully"}), 200

if __name__ == "__main__":
  app.run(debug=True)