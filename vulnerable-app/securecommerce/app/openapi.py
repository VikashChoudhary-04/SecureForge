"""OpenAPI specification for SecureCommerce."""

from **future** import annotations

from flask import Blueprint, jsonify

openapi_bp = Blueprint(
"openapi",
**name**,
)

OPENAPI_SPEC = {
"openapi": "3.0.3",
"info": {
"title": "SecureCommerce API",
"description": (
"Deliberately vulnerable REST API used "
"for SecureForge security testing."
),
"version": "0.1.0",
},
"servers": [
{
"url": "/",
}
],
"paths": {
"/api/health": {
"get": {
"summary": "API health check",
"responses": {
"200": {
"description": "API is healthy"
}
},
}
},
"/api/users": {
"get": {
"summary": "List users",
"responses": {
"200": {
"description": "User list"
}
},
}
},
"/api/users/{user_id}": {
"get": {
"summary": "Get a user",
"parameters": [
{
"name": "user_id",
"in": "path",
"required": True,
"schema": {
"type": "integer",
},
}
],
"responses": {
"200": {
"description": "User details"
},
"404": {
"description": "User not found"
},
},
}
},
"/api/products": {
"get": {
"summary": "List products",
"responses": {
"200": {
"description": "Product list"
}
},
},
"post": {
"summary": "Create product",
"responses": {
"201": {
"description": "Product created"
}
},
},
},
"/api/products/{product_id}": {
"get": {
"summary": "Get a product",
"parameters": [
{
"name": "product_id",
"in": "path",
"required": True,
"schema": {
"type": "integer",
},
}
],
"responses": {
"200": {
"description": "Product details"
},
"404": {
"description": "Product not found"
},
},
}
},
"/api/orders": {
"get": {
"summary": "List orders for a user",
"parameters": [
{
"name": "user_id",
"in": "query",
"required": True,
"schema": {
"type": "integer",
},
}
],
"responses": {
"200": {
"description": "Order list"
}
},
},
"post": {
"summary": "Create an order",
"requestBody": {
"required": True,
"content": {
"application/json": {
"schema": {
"$ref": (
"#/components/schemas/"
"CreateOrderRequest"
)
}
}
},
},
"responses": {
"201": {
"description": "Order created"
}
},
},
},
"/api/orders/{order_id}": {
"get": {
"summary": "Get an order",
"parameters": [
{
"name": "order_id",
"in": "path",
"required": True,
"schema": {
"type": "integer",
},
}
],
"responses": {
"200": {
"description": "Order details"
},
"404": {
"description": "Order not found"
},
},
}
},
"/api/admin/users": {
"get": {
"summary": "Administrative user listing",
"responses": {
"200": {
"description": "Administrative user data"
}
},
}
},
},
"components": {
"schemas": {
"CreateOrderRequest": {
"type": "object",
"required": [
"user_id",
"shipping_address",
"items",
],
"properties": {
"user_id": {
"type": "integer",
},
"shipping_address": {
"type": "string",
},
"items": {
"type": "array",
"items": {
"$ref": (
"#/components/schemas/"
"OrderItemRequest"
)
},
},
},
},
"OrderItemRequest": {
"type": "object",
"required": [
"product_id",
"quantity",
],
"properties": {
"product_id": {
"type": "integer",
},
"quantity": {
"type": "integer",
"minimum": 1,
},
},
},
}
},
}

@openapi_bp.get("/openapi.json")
def openapi():
"""Return the SecureCommerce OpenAPI specification."""
return jsonify(OPENAPI_SPEC)
