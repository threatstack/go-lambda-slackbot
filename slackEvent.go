// Lambda and Slack API demo code
// Copyright (c) 2020 Threat Stack, Inc.
// Author: Patrick Cable
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the 
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	log "github.com/sirupsen/logrus"
	"github.com/slack-go/slack"
	"github.com/slack-go/slack/slackevents"
)

func receiveSlackEvent(req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	if os.Getenv("SIGNING_SECRET") == "" {
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, fmt.Errorf("No signing secret, cant run")
	}
	if os.Getenv("SLACK_API_KEY") == "" {
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, fmt.Errorf("No slack API key, cant run")
	}
	apiKey := os.Getenv("SLACK_API_KEY")
	setLogLevel(os.Getenv("LOGLEVEL"))

	// Verify the hmac you get from Slack
	if !verifyReq(os.Getenv("SIGNING_SECRET"), req.Headers["X-Slack-Request-Timestamp"], req.Body, req.Headers["X-Slack-Signature"]) {
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, fmt.Errorf("Invalid secret")
	}

	// We don't verify the token because that's being phased out. We did the hmac verification above anyways.
	eventsAPIEvent, err := slackevents.ParseEvent(json.RawMessage(req.Body), slackevents.OptionNoVerifyToken())
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}, fmt.Errorf("Unable to decode API event: %s", err)
	}

	// Actual Events
	// Slack sends a challenge to make sure your app can actually handle EventAPI stuff instead of spamming some rando host
	if eventsAPIEvent.Type == slackevents.URLVerification {
		log.Debug("Received Slack URL Verification request")
		return events.APIGatewayProxyResponse{StatusCode: http.StatusOK, Body: req.Body}, nil
	}

	// Set up an API client to send a response if we need to
	api := slack.New(apiKey)

	// This is the MEAT right here. Take in a callback event, and theres an _inner event_ that
	// is an interface and you define based on that case statement.
	if eventsAPIEvent.Type == slackevents.CallbackEvent {
		innerEvent := eventsAPIEvent.InnerEvent
		switch ev := innerEvent.Data.(type) {
		case *slackevents.MessageEvent:
			switch ev.Text {
			case "it's showtime!":
				_, _, err := api.PostMessage(ev.Channel, slack.MsgOptionText("Yes, it is!", false))
				if err != nil {
					log.Debugf("Unable to post slack message: %s", err.Error())
				}
			}
		}
	}
	return events.APIGatewayProxyResponse{StatusCode: http.StatusOK}, nil
}

// verifyReq - verifies the hmac that slack sent us using our secret bits
// more info: https://api.slack.com/docs/verifying-requests-from-slack
func verifyReq(secret string, timestamp string, body string, signature string) bool {
	validation := fmt.Sprintf("v0:%s:%s", timestamp, body)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(validation))
	sha := fmt.Sprintf("v0=%s", hex.EncodeToString(h.Sum(nil)))
	return hmac.Equal([]byte(sha), []byte(signature))
}

// setLogLevel - a convenience function to make receiveSlackEvent easier to read.
func setLogLevel(level string) {
	switch level {
	case "debug":
		log.SetLevel(log.DebugLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}
}

func main() {
	lambda.Start(receiveSlackEvent)
}
