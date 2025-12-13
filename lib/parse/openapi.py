#!/usr/bin/env python

"""
Copyright (c) 2006-2025 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

import json
import re

from lib.core.common import getSafeExString
from lib.core.data import conf
from lib.core.data import logger
from lib.core.datatype import OrderedSet
from lib.core.exception import SqlmapDataException
from thirdparty.six.moves import urllib as _urllib

def parseOpenAPI(content, baseUrl=None):
    """
    Parses OpenAPI/Swagger specification content and extracts API endpoints.

    @param content: OpenAPI/Swagger specification content (JSON or YAML string)
    @type content: str
    @param baseUrl: Base URL for the API (used if not specified in spec)
    @type baseUrl: str
    @return: set of (url, method, data, cookie, headers) tuples
    @rtype: OrderedSet
    """

    retVal = OrderedSet()
    spec = None

    try:
        spec = json.loads(content)
    except ValueError:
        try:
            import yaml
            spec = yaml.safe_load(content)
        except ImportError:
            errMsg = "OpenAPI YAML parsing requires the 'PyYAML' package. "
            errMsg += "Please install it (e.g., 'pip install PyYAML') or use JSON format"
            raise SqlmapDataException(errMsg)
        except Exception as ex:
            errMsg = "failed to parse OpenAPI specification ('%s')" % getSafeExString(ex)
            raise SqlmapDataException(errMsg)

    if not isinstance(spec, dict):
        errMsg = "invalid OpenAPI specification format"
        raise SqlmapDataException(errMsg)

    # Determine OpenAPI version
    isOpenAPI3 = "openapi" in spec
    isSwagger2 = "swagger" in spec

    if not isOpenAPI3 and not isSwagger2:
        errMsg = "unrecognized API specification format. "
        errMsg += "Please provide a valid OpenAPI 3.x or Swagger 2.x specification"
        raise SqlmapDataException(errMsg)

    # Extract base URL
    apiBaseUrl = None
    if isOpenAPI3:
        servers = spec.get("servers", [])
        if servers and isinstance(servers, list):
            apiBaseUrl = servers[0].get("url", "")
    elif isSwagger2:
        host = spec.get("host", "")
        basePath = spec.get("basePath", "")
        schemes = spec.get("schemes", ["https"])
        scheme = schemes[0] if schemes else "https"
        if host:
            apiBaseUrl = "%s://%s%s" % (scheme, host, basePath)

    # Use provided baseUrl as fallback
    if not apiBaseUrl and baseUrl:
        apiBaseUrl = baseUrl.rstrip('/')
    elif not apiBaseUrl:
        errMsg = "no base URL found in OpenAPI specification. "
        errMsg += "Please provide the target URL with -u option"
        raise SqlmapDataException(errMsg)

    # Handle relative URLs in OpenAPI 3.x servers
    if apiBaseUrl and not apiBaseUrl.startswith(("http://", "https://")):
        if baseUrl:
            apiBaseUrl = _urllib.parse.urljoin(baseUrl, apiBaseUrl)
        else:
            apiBaseUrl = "https://" + apiBaseUrl.lstrip('/')

    paths = spec.get("paths", {})
    if not paths:
        warnMsg = "no API paths found in OpenAPI specification"
        logger.warning(warnMsg)
        return retVal

    infoMsg = "found %d API path(s) in OpenAPI specification" % len(paths)
    logger.info(infoMsg)

    for path, pathItem in paths.items():
        if not isinstance(pathItem, dict):
            continue

        for method, operation in pathItem.items():
            if method.lower() not in ("get", "post", "put", "delete", "patch", "options", "head"):
                continue

            if not isinstance(operation, dict):
                continue

            url = apiBaseUrl.rstrip('/') + path
            httpMethod = method.upper()
            data = None
            queryParams = []
            pathParams = {}

            # Extract parameters
            parameters = operation.get("parameters", [])

            # Also include path-level parameters
            pathLevelParams = pathItem.get("parameters", [])
            if pathLevelParams:
                parameters = pathLevelParams + parameters

            for param in parameters:
                if not isinstance(param, dict):
                    continue

                # Handle $ref for parameters
                if "$ref" in param:
                    param = _resolveRef(param["$ref"], spec)
                    if not param:
                        continue

                paramName = param.get("name", "")
                paramIn = param.get("in", "")
                paramSchema = param.get("schema", {})

                # Generate a sample value based on type
                sampleValue = _getSampleValue(param, paramSchema)

                if paramIn == "query":
                    queryParams.append("%s=%s" % (paramName, sampleValue))
                elif paramIn == "path":
                    pathParams[paramName] = sampleValue
                elif paramIn == "body":
                    # Swagger 2.x body parameter
                    data = _getRequestBody(param.get("schema", {}), spec)
                elif paramIn == "formData":
                    if data is None:
                        data = ""
                    if data:
                        data += "&"
                    data += "%s=%s" % (paramName, sampleValue)

            # Handle OpenAPI 3.x requestBody
            if isOpenAPI3:
                requestBody = operation.get("requestBody", {})
                if requestBody:
                    bodyContent = requestBody.get("content", {})
                    # Prefer JSON content type
                    for contentType in ("application/json", "application/x-www-form-urlencoded", "multipart/form-data"):
                        if contentType in bodyContent:
                            mediaType = bodyContent[contentType]
                            schema = mediaType.get("schema", {})
                            if contentType == "application/json":
                                data = _getRequestBody(schema, spec)
                            else:
                                data = _getFormDataBody(schema, spec)
                            break

            # Replace path parameters in URL
            for paramName, paramValue in pathParams.items():
                url = url.replace("{%s}" % paramName, str(paramValue))

            # Remove any unreplaced path parameters
            url = re.sub(r"\{[^}]+\}", "1", url)

            # Add query parameters to URL
            if queryParams:
                separator = "&" if "?" in url else "?"
                url = url + separator + "&".join(queryParams)

            retVal.add((url, httpMethod, data, conf.cookie, None))

    if retVal:
        infoMsg = "extracted %d testable endpoint(s) from OpenAPI specification" % len(retVal)
        logger.info(infoMsg)
    else:
        warnMsg = "no testable endpoints found in OpenAPI specification"
        logger.warning(warnMsg)

    return retVal


def _getTypeAndFormat(param, schema):
    """
    Extract type and format from parameter or schema.
    """
    
    if isinstance(schema, dict):
        paramType = schema.get("type", param.get("type", "string"))
        paramFormat = schema.get("format", param.get("format", ""))
    else:
        paramType = param.get("type", "string")
        paramFormat = param.get("format", "")

    return paramType, paramFormat


def _getSampleValue(param, schema):
    """
    Generate a sample value based on parameter/schema type.
    """
    
    # Check for example value first
    if "example" in param:
        return param["example"]
    if "default" in param:
        return param["default"]
    if isinstance(schema, dict):
        if "example" in schema:
            return schema["example"]
        if "default" in schema:
            return schema["default"]

    paramType, paramFormat = _getTypeAndFormat(param, schema)

    if paramType == "integer":
        return "1"
    elif paramType == "number":
        return "1.0"
    elif paramType == "boolean":
        return "true"
    elif paramType == "array":
        return "1"
    elif paramFormat == "uuid":
        return "550e8400-e29b-41d4-a716-446655440000"
    elif paramFormat == "email":
        return "test@example.com"
    elif paramFormat == "date":
        return "2024-01-01"
    elif paramFormat == "date-time":
        return "2024-01-01T00:00:00Z"
    else:
        return "test"


def _getRequestBody(schema, spec):
    """
    Generate sample JSON request body from schema.
    """
    
    import json
    body = _schemaToSample(schema, spec)
    if body is not None:
        return json.dumps(body)
    return None


def _getFormDataBody(schema, spec):
    """
    Generate form data body from schema.
    """
    
    properties = schema.get("properties", {})
    if not properties:
        return None

    parts = []
    for propName, propSchema in properties.items():
        value = _getSampleValue({}, propSchema)
        parts.append("%s=%s" % (propName, value))

    return "&".join(parts) if parts else None


def _schemaToSample(schema, spec, depth=0):
    """
    Convert JSON schema to sample value.
    """
    
    if depth > 5:  # Prevent infinite recursion
        return None

    if not isinstance(schema, dict):
        return None

    # Handle $ref
    if "$ref" in schema:
        refPath = schema["$ref"]
        schema = _resolveRef(refPath, spec)
        if not schema:
            return None

    schemaType = schema.get("type", "object")

    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]

    if schemaType == "object":
        result = {}
        properties = schema.get("properties", {})
        for propName, propSchema in properties.items():
            value = _schemaToSample(propSchema, spec, depth + 1)
            if value is not None:
                result[propName] = value
            else:
                result[propName] = _getSampleValue({}, propSchema)
        return result if result else {"key": "value"}

    elif schemaType == "array":
        items = schema.get("items", {})
        itemValue = _schemaToSample(items, spec, depth + 1)
        if itemValue is not None:
            return [itemValue]
        return [_getSampleValue({}, items)]

    elif schemaType == "string":
        return _getSampleValue({}, schema)
    elif schemaType == "integer":
        return 1
    elif schemaType == "number":
        return 1.0
    elif schemaType == "boolean":
        return True
    else:
        return "test"


def _resolveRef(ref, spec):
    """
    Resolve a JSON reference ($ref) in the specification.
    """
    
    if not ref.startswith("#/"):
        return None

    parts = ref[2:].split("/")
    current = spec

    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None

    return current
