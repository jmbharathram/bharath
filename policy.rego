package rules

default allow = false

users := {
    "alice":   {"manager": "charlie", "title": "salesperson"},
    "bob":     {"manager": "charlie", "title": "salesperson"},
    "charlie": {"manager": "dave",    "title": "manager"},
    "dave":    {"manager": null,      "title": "ceo"}
}

allow {
  input.path == ["cars"]
  input.method == "GET"
}

allow {
    input.path == ["cars"]
    input.method == "POST"
    user_is_manager
}

allow {
    input.path[0] == "cars"
    is_string(input.path[1])
    input.method == "GET"
    user_is_employee
}

allow {
    input.path[0] == "cars"
    is_string(input.path[1])
    input.method == "PUT"
    users[input.user][title] == "manager"
}

allow {
    input.path[0] == "cars"
    is_string(input.path[1])
    input.method == "DELETE"
    
}

allow {
    input.path[0] == "cars"
    is_string(input.path[1])
    input.path[2] == "status"
    input.method == "GET"
    users[input.user]
}

allow {
    input.path[0] == "cars"
    is_string(input.path[1])
    input.path[2] == "status"
    input.method == "POST"
    
}

user_is_employee {
    users[input.user]
}

user_is_manager {
    users[input.user][title] == "manager"
}

test_car_read_positive {
    in = {
       "method": "GET",
       "path": ["cars"],
       "user": "alice"
    }
    allow == true with input as in
}

test_car_read_negative {
    in = {
       "method": "GET",
       "path": ["nonexistent"],
       "user": "alice"
    }
    allow == false with input as in
}
