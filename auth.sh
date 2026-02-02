#!/bin/bash

BASE_URL="${KIRO_GATEWAY_URL:-http://localhost:8000}"

usage() {
    echo "Usage: $0 <command> [args]"
    echo ""
    echo "Commands:"
    echo "  login [start_url]    Start device auth flow (optional: organization SSO URL)"
    echo "  status <session_id>  Check login status"
    echo "  cancel <session_id>  Cancel login session"
    echo ""
    echo "Examples:"
    echo "  $0 login                                           # Builder ID login"
    echo "  $0 login https://my-company.awsapps.com/start      # Organization SSO"
    echo "  $0 status abc123-uuid"
    echo "  $0 cancel abc123-uuid"
    echo ""
    echo "Environment:"
    echo "  KIRO_GATEWAY_URL    Base URL (default: http://localhost:8000)"
    exit 1
}

interactive() {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Kiro Gateway Authentication"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "  1) Builder ID (personal)"
    echo "  2) Organization SSO"
    echo "  3) Check status"
    echo "  4) Cancel session"
    echo "  5) Exit"
    echo ""
    read -p "  Select option [1-5]: " choice
    echo ""
    
    case "$choice" in
        1)
            login
            poll_status
            ;;
        2)
            read -p "  Enter SSO start URL: " start_url
            if [ -z "$start_url" ]; then
                echo "  Error: SSO URL required"
                exit 1
            fi
            login "$start_url"
            poll_status
            ;;
        3)
            read -p "  Enter session ID: " session_id
            status "$session_id"
            ;;
        4)
            read -p "  Enter session ID: " session_id
            cancel "$session_id"
            ;;
        5)
            exit 0
            ;;
        *)
            echo "  Invalid option"
            exit 1
            ;;
    esac
}

login() {
    local start_url="$1"
    local url="$BASE_URL/auth/login"
    
    if [ -n "$start_url" ]; then
        url="$url?start_url=$start_url"
    fi
    
    response=$(curl -s -X POST "$url")
    
    if echo "$response" | grep -q '"detail"'; then
        echo "Error: $response"
        exit 1
    fi
    
    SESSION_ID=$(echo "$response" | grep -o '"session_id":"[^"]*"' | cut -d'"' -f4)
    user_code=$(echo "$response" | grep -o '"user_code":"[^"]*"' | cut -d'"' -f4)
    verification_uri=$(echo "$response" | grep -o '"verification_uri_complete":"[^"]*"' | cut -d'"' -f4)
    expires_in=$(echo "$response" | grep -o '"expires_in":[0-9]*' | cut -d':' -f2)
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Device Authorization"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "  1. Open this URL in your browser:"
    echo "     $verification_uri"
    echo ""
    echo "  2. Enter code: $user_code"
    echo ""
    echo "  Session ID: $SESSION_ID"
    echo "  Expires in: ${expires_in}s"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

poll_status() {
    if [ -z "$SESSION_ID" ]; then
        return
    fi
    
    echo ""
    echo "  Waiting for authentication..."
    echo "  (Press Ctrl+C to cancel)"
    echo ""
    
    while true; do
        response=$(curl -s "$BASE_URL/auth/login/status/$SESSION_ID")
        status_val=$(echo "$response" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
        
        case "$status_val" in
            pending)
                printf "  ⏳ Waiting...\r"
                sleep 2
                ;;
            complete)
                echo "  ✓ Authentication complete - credentials saved!"
                echo ""
                exit 0
                ;;
            expired)
                echo "  ✗ Session expired"
                exit 1
                ;;
            error)
                message=$(echo "$response" | grep -o '"message":"[^"]*"' | cut -d'"' -f4)
                echo "  ✗ Error: $message"
                exit 1
                ;;
            *)
                echo "  ✗ Unknown status: $response"
                exit 1
                ;;
        esac
    done
}

status() {
    local session_id="$1"
    
    if [ -z "$session_id" ]; then
        echo "Error: session_id required"
        usage
    fi
    
    response=$(curl -s "$BASE_URL/auth/login/status/$session_id")
    status_val=$(echo "$response" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
    message=$(echo "$response" | grep -o '"message":"[^"]*"' | cut -d'"' -f4)
    
    case "$status_val" in
        pending)
            echo "⏳ Pending - waiting for user to complete authentication"
            ;;
        complete)
            echo "✓ Complete - credentials saved"
            ;;
        expired)
            echo "✗ Expired - device code timed out"
            ;;
        error)
            echo "✗ Error: $message"
            ;;
        *)
            echo "$response"
            ;;
    esac
}

cancel() {
    local session_id="$1"
    
    if [ -z "$session_id" ]; then
        echo "Error: session_id required"
        usage
    fi
    
    curl -s -X DELETE "$BASE_URL/auth/login/$session_id"
    echo "Session cancelled"
}

if [ -z "$1" ]; then
    interactive
    exit 0
fi

case "$1" in
    login)
        login "$2"
        ;;
    status)
        status "$2"
        ;;
    cancel)
        cancel "$2"
        ;;
    *)
        usage
        ;;
esac
