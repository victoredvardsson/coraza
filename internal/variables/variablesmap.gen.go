// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Code generated by types/variables/generator DO NOT EDIT.

package variables

import (
	"errors"
	"strings"
)

// Name transforms a VARIABLE representation
// into a string, it's used for audit and logging
func (v RuleVariable) Name() string {
	switch v {
	case Unknown:
		return "UNKNOWN"
	case ResponseContentType:
		return "RESPONSE_CONTENT_TYPE"
	case UniqueID:
		return "UNIQUE_ID"
	case ArgsCombinedSize:
		return "ARGS_COMBINED_SIZE"
	case FilesCombinedSize:
		return "FILES_COMBINED_SIZE"
	case FullRequestLength:
		return "FULL_REQUEST_LENGTH"
	case InboundDataError:
		return "INBOUND_DATA_ERROR"
	case MatchedVar:
		return "MATCHED_VAR"
	case MatchedVarName:
		return "MATCHED_VAR_NAME"
	case MultipartDataAfter:
		return "MULTIPART_DATA_AFTER"
	case OutboundDataError:
		return "OUTBOUND_DATA_ERROR"
	case QueryString:
		return "QUERY_STRING"
	case RemoteAddr:
		return "REMOTE_ADDR"
	case RemoteHost:
		return "REMOTE_HOST"
	case RemotePort:
		return "REMOTE_PORT"
	case ReqbodyError:
		return "REQBODY_ERROR"
	case ReqbodyErrorMsg:
		return "REQBODY_ERROR_MSG"
	case ReqbodyProcessorError:
		return "REQBODY_PROCESSOR_ERROR"
	case ReqbodyProcessorErrorMsg:
		return "REQBODY_PROCESSOR_ERROR_MSG"
	case ReqbodyProcessor:
		return "REQBODY_PROCESSOR"
	case RequestBasename:
		return "REQUEST_BASENAME"
	case RequestBody:
		return "REQUEST_BODY"
	case RequestBodyLength:
		return "REQUEST_BODY_LENGTH"
	case RequestFilename:
		return "REQUEST_FILENAME"
	case RequestLine:
		return "REQUEST_LINE"
	case RequestMethod:
		return "REQUEST_METHOD"
	case RequestProtocol:
		return "REQUEST_PROTOCOL"
	case RequestURI:
		return "REQUEST_URI"
	case RequestURIRaw:
		return "REQUEST_URI_RAW"
	case ResponseBody:
		return "RESPONSE_BODY"
	case ResponseContentLength:
		return "RESPONSE_CONTENT_LENGTH"
	case ResponseProtocol:
		return "RESPONSE_PROTOCOL"
	case ResponseStatus:
		return "RESPONSE_STATUS"
	case ServerAddr:
		return "SERVER_ADDR"
	case ServerName:
		return "SERVER_NAME"
	case ServerPort:
		return "SERVER_PORT"
	case HighestSeverity:
		return "HIGHEST_SEVERITY"
	case StatusLine:
		return "STATUS_LINE"
	case Duration:
		return "DURATION"
	case ResponseHeadersNames:
		return "RESPONSE_HEADERS_NAMES"
	case RequestHeadersNames:
		return "REQUEST_HEADERS_NAMES"
	case Args:
		return "ARGS"
	case ArgsGet:
		return "ARGS_GET"
	case ArgsPost:
		return "ARGS_POST"
	case ArgsPath:
		return "ARGS_PATH"
	case FilesSizes:
		return "FILES_SIZES"
	case FilesNames:
		return "FILES_NAMES"
	case FilesTmpContent:
		return "FILES_TMP_CONTENT"
	case MultipartFilename:
		return "MULTIPART_FILENAME"
	case MultipartName:
		return "MULTIPART_NAME"
	case MatchedVarsNames:
		return "MATCHED_VARS_NAMES"
	case MatchedVars:
		return "MATCHED_VARS"
	case Files:
		return "FILES"
	case RequestCookies:
		return "REQUEST_COOKIES"
	case RequestHeaders:
		return "REQUEST_HEADERS"
	case ResponseHeaders:
		return "RESPONSE_HEADERS"
	case ResBodyProcessor:
		return "RES_BODY_PROCESSOR"
	case Geo:
		return "GEO"
	case RequestCookiesNames:
		return "REQUEST_COOKIES_NAMES"
	case FilesTmpNames:
		return "FILES_TMPNAMES"
	case ArgsNames:
		return "ARGS_NAMES"
	case ArgsGetNames:
		return "ARGS_GET_NAMES"
	case ArgsPostNames:
		return "ARGS_POST_NAMES"
	case TX:
		return "TX"
	case Rule:
		return "RULE"
	case JSON:
		return "JSON"
	case Env:
		return "ENV"
	case UrlencodedError:
		return "URLENCODED_ERROR"
	case ResponseArgs:
		return "RESPONSE_ARGS"
	case ResponseXML:
		return "RESPONSE_XML"
	case RequestXML:
		return "REQUEST_XML"
	case XML:
		return "XML"
	case MultipartPartHeaders:
		return "MULTIPART_PART_HEADERS"
	case AuthType:
		return "AUTH_TYPE"
	case FullRequest:
		return "FULL_REQUEST"
	case MultipartBoundaryQuoted:
		return "MULTIPART_BOUNDARY_QUOTED"
	case MultipartBoundaryWhitespace:
		return "MULTIPART_BOUNDARY_WHITESPACE"
	case MultipartCrlfLfLines:
		return "MULTIPART_CRLF_LF_LINES"
	case MultipartDataBefore:
		return "MULTIPART_DATA_BEFORE"
	case MultipartFileLimitExceeded:
		return "MULTIPART_FILE_LIMIT_EXCEEDED"
	case MultipartHeaderFolding:
		return "MULTIPART_HEADER_FOLDING"
	case MultipartInvalidHeaderFolding:
		return "MULTIPART_INVALID_HEADER_FOLDING"
	case MultipartInvalidPart:
		return "MULTIPART_INVALID_PART"
	case MultipartInvalidQuoting:
		return "MULTIPART_INVALID_QUOTING"
	case MultipartLfLine:
		return "MULTIPART_LF_LINE"
	case MultipartMissingSemicolon:
		return "MULTIPART_MISSING_SEMICOLON"
	case MultipartStrictError:
		return "MULTIPART_STRICT_ERROR"
	case MultipartUnmatchedBoundary:
		return "MULTIPART_UNMATCHED_BOUNDARY"
	case PathInfo:
		return "PATH_INFO"
	case Sessionid:
		return "SESSIONID"
	case Userid:
		return "USERID"
	case IP:
		return "IP"
	case ResBodyError:
		return "RES_BODY_ERROR"
	case ResBodyErrorMsg:
		return "RES_BODY_ERROR_MSG"
	case ResBodyProcessorError:
		return "RES_BODY_PROCESSOR_ERROR"
	case ResBodyProcessorErrorMsg:
		return "RES_BODY_PROCESSOR_ERROR_MSG"

	default:
		return "INVALID_VARIABLE"
	}
}

var rulemapRev = map[string]RuleVariable{
	"UNKNOWN":                          Unknown,
	"RESPONSE_CONTENT_TYPE":            ResponseContentType,
	"UNIQUE_ID":                        UniqueID,
	"ARGS_COMBINED_SIZE":               ArgsCombinedSize,
	"FILES_COMBINED_SIZE":              FilesCombinedSize,
	"FULL_REQUEST_LENGTH":              FullRequestLength,
	"INBOUND_DATA_ERROR":               InboundDataError,
	"MATCHED_VAR":                      MatchedVar,
	"MATCHED_VAR_NAME":                 MatchedVarName,
	"MULTIPART_DATA_AFTER":             MultipartDataAfter,
	"OUTBOUND_DATA_ERROR":              OutboundDataError,
	"QUERY_STRING":                     QueryString,
	"REMOTE_ADDR":                      RemoteAddr,
	"REMOTE_HOST":                      RemoteHost,
	"REMOTE_PORT":                      RemotePort,
	"REQBODY_ERROR":                    ReqbodyError,
	"REQBODY_ERROR_MSG":                ReqbodyErrorMsg,
	"REQBODY_PROCESSOR_ERROR":          ReqbodyProcessorError,
	"REQBODY_PROCESSOR_ERROR_MSG":      ReqbodyProcessorErrorMsg,
	"REQBODY_PROCESSOR":                ReqbodyProcessor,
	"REQUEST_BASENAME":                 RequestBasename,
	"REQUEST_BODY":                     RequestBody,
	"REQUEST_BODY_LENGTH":              RequestBodyLength,
	"REQUEST_FILENAME":                 RequestFilename,
	"REQUEST_LINE":                     RequestLine,
	"REQUEST_METHOD":                   RequestMethod,
	"REQUEST_PROTOCOL":                 RequestProtocol,
	"REQUEST_URI":                      RequestURI,
	"REQUEST_URI_RAW":                  RequestURIRaw,
	"RESPONSE_BODY":                    ResponseBody,
	"RESPONSE_CONTENT_LENGTH":          ResponseContentLength,
	"RESPONSE_PROTOCOL":                ResponseProtocol,
	"RESPONSE_STATUS":                  ResponseStatus,
	"SERVER_ADDR":                      ServerAddr,
	"SERVER_NAME":                      ServerName,
	"SERVER_PORT":                      ServerPort,
	"HIGHEST_SEVERITY":                 HighestSeverity,
	"STATUS_LINE":                      StatusLine,
	"DURATION":                         Duration,
	"RESPONSE_HEADERS_NAMES":           ResponseHeadersNames,
	"REQUEST_HEADERS_NAMES":            RequestHeadersNames,
	"ARGS":                             Args,
	"ARGS_GET":                         ArgsGet,
	"ARGS_POST":                        ArgsPost,
	"ARGS_PATH":                        ArgsPath,
	"FILES_SIZES":                      FilesSizes,
	"FILES_NAMES":                      FilesNames,
	"FILES_TMP_CONTENT":                FilesTmpContent,
	"MULTIPART_FILENAME":               MultipartFilename,
	"MULTIPART_NAME":                   MultipartName,
	"MATCHED_VARS_NAMES":               MatchedVarsNames,
	"MATCHED_VARS":                     MatchedVars,
	"FILES":                            Files,
	"REQUEST_COOKIES":                  RequestCookies,
	"REQUEST_HEADERS":                  RequestHeaders,
	"RESPONSE_HEADERS":                 ResponseHeaders,
	"RES_BODY_PROCESSOR":               ResBodyProcessor,
	"GEO":                              Geo,
	"REQUEST_COOKIES_NAMES":            RequestCookiesNames,
	"FILES_TMPNAMES":                   FilesTmpNames,
	"ARGS_NAMES":                       ArgsNames,
	"ARGS_GET_NAMES":                   ArgsGetNames,
	"ARGS_POST_NAMES":                  ArgsPostNames,
	"TX":                               TX,
	"RULE":                             Rule,
	"JSON":                             JSON,
	"ENV":                              Env,
	"URLENCODED_ERROR":                 UrlencodedError,
	"RESPONSE_ARGS":                    ResponseArgs,
	"RESPONSE_XML":                     ResponseXML,
	"REQUEST_XML":                      RequestXML,
	"XML":                              XML,
	"MULTIPART_PART_HEADERS":           MultipartPartHeaders,
	"AUTH_TYPE":                        AuthType,
	"FULL_REQUEST":                     FullRequest,
	"MULTIPART_BOUNDARY_QUOTED":        MultipartBoundaryQuoted,
	"MULTIPART_BOUNDARY_WHITESPACE":    MultipartBoundaryWhitespace,
	"MULTIPART_CRLF_LF_LINES":          MultipartCrlfLfLines,
	"MULTIPART_DATA_BEFORE":            MultipartDataBefore,
	"MULTIPART_FILE_LIMIT_EXCEEDED":    MultipartFileLimitExceeded,
	"MULTIPART_HEADER_FOLDING":         MultipartHeaderFolding,
	"MULTIPART_INVALID_HEADER_FOLDING": MultipartInvalidHeaderFolding,
	"MULTIPART_INVALID_PART":           MultipartInvalidPart,
	"MULTIPART_INVALID_QUOTING":        MultipartInvalidQuoting,
	"MULTIPART_LF_LINE":                MultipartLfLine,
	"MULTIPART_MISSING_SEMICOLON":      MultipartMissingSemicolon,
	"MULTIPART_STRICT_ERROR":           MultipartStrictError,
	"MULTIPART_UNMATCHED_BOUNDARY":     MultipartUnmatchedBoundary,
	"PATH_INFO":                        PathInfo,
	"SESSIONID":                        Sessionid,
	"USERID":                           Userid,
	"IP":                               IP,
	"RES_BODY_ERROR":                   ResBodyError,
	"RES_BODY_ERROR_MSG":               ResBodyErrorMsg,
	"RES_BODY_PROCESSOR_ERROR":         ResBodyProcessorError,
	"RES_BODY_PROCESSOR_ERROR_MSG":     ResBodyProcessorErrorMsg,
}

var errUnknownVariable = errors.New("unknown variable")

// Parse returns the byte interpretation
// of a variable from a string
// Returns error if there is no representation
func Parse(v string) (RuleVariable, error) {
	if v, ok := rulemapRev[strings.ToUpper(v)]; ok {
		return v, nil
	}
	return Unknown, errUnknownVariable
}