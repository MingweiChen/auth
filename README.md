# In-memory Authorization Http RESTful API

## Environment
JDK 18 + Spring Boot

Intellj + Maven

Mac OS Monterey 12.3.1

## Start Guild
Start your IDE and simply run the project or com/example/auth/AuthApplication.java.
Use any online http debugging tool you prefer or curl or something else.

A typical request:
````
POST http://localhost:8080/auth
Content-Type: application/json
[{
  "action": "check_role",
  "roleName": "abc-r1",
  "token": "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyTmFtZSI6ImFiYyIsImV4cCI6MTY1NDE4ODU5OX0.EsVZUIaZkL0MDu-c-WWGawlEVT-sile5cALbXg9X3fQ"
}]
````
## Unit test
Some unit tests were added to guard critical user journeys, but corner cases are not covered 100%.


# Additional Dependencies
JWT - to sign web tokens.

Spring Boot and its artifacts - to start http service and simplify request and response handling.
