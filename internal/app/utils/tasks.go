package utils

import (
	"encoding/json"
	"fmt"
	logdoc "github.com/LogDoc-org/logdoc-go-appender/logrus"
	"github.com/gurkankaymak/hocon"
	"github.com/hibiken/asynq"
	"github.com/opentracing/opentracing-go"
	"github.com/uber/jaeger-client-go"
	"time"
)

const (
	TypeTelegramDelivery  = "telegram:delivery"
	TypeEmailDelivery     = "email:delivery"
	TypeEmailVerification = "email:verification"
	TypePasswordReset     = "password:reset"
)

type TelegramPayload struct {
	UserID  int
	Content string
}

type EmailPayload struct {
	Name    string
	From    string
	Subject string
	Email   string
	Content string
}

func CreateTask(config *hocon.Config, span opentracing.Span, taskType string, name string, email string, userID int, content string) error {
	logger := logdoc.GetLogger()

	var task *asynq.Task
	var err error

	if sc, ok := span.Context().(jaeger.SpanContext); ok {
		id := sc.TraceID()
		client := asynq.NewClient(asynq.RedisClientOpt{Addr: fmt.Sprintf("%s:%d", config.GetString("redis.host"), config.GetInt("redis.port"))})
		defer client.Close()

		switch taskType {
		case TypeTelegramDelivery:
			message := fmt.Sprintf("%s\n[Trace is here](https://%s/%s", content, config.GetString("trace.address"), id.String())
			task, err = NewTelegramDeliveryTask(userID, message)
			if err != nil {
				logger.Error("could not create task: %v", err)
				return err
			}
		case TypeEmailVerification:
			task, err = NewEmailTask(name, "verify@<domain>", "demo registration. Verification email", email, content)
			if err != nil {
				logger.Error("could not create task: %v", err)
				return err
			}
		case TypePasswordReset:
			task, err = NewEmailTask(name, "reset@<domain>", "demo. Password reset email", email, content)
			if err != nil {
				logger.Error("could not create task: %v", err)
				return err
			}
		}

		// Enqueue task to be processed in the queue. The task will be unique and enqueued at most once.
		// Uniqueness of a task is based on the following properties:
		//     - Task Type
		//     - Task Payload - we have a problem here, because we have different user notification codes for our emails
		//     - Queue Name
		info, err := client.Enqueue(task, asynq.Queue("critical"), asynq.Unique(time.Hour))
		if err != nil {
			logger.Error("could not enqueue task: %v", err)
			return err
		}
		logger.Printf("enqueued task: id=%s queue=%s", info.ID, info.Queue)
	}
	return nil
}

func NewTelegramDeliveryTask(userID int, content string) (*asynq.Task, error) {
	payload, err := json.Marshal(TelegramPayload{UserID: userID, Content: content})
	if err != nil {
		return nil, err
	}
	return asynq.NewTask(TypeTelegramDelivery, payload), nil
}

func NewEmailTask(name string, from string, subject string, email string, content string) (*asynq.Task, error) {
	payload, err := json.Marshal(EmailPayload{Name: name, From: from, Subject: subject, Email: email, Content: content})
	if err != nil {
		return nil, err
	}
	return asynq.NewTask(TypeEmailDelivery, payload), nil
}
