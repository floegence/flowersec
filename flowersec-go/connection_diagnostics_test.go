package flowersec

import "testing"

func TestNilControllerLocalReportUsesCurrentDetachedPublicShape(t *testing.T) {
	var controller *ConnectionController
	report := controller.LocalReport()
	if report.Constraint != "unavailable" || report.Connection.SpendState != "unknown" || report.Connection.Spent != nil || report.Reservation != "not_reserved" {
		t.Fatal("ownerless Controller invented local facts", report)
	}
	if report.Required != nil || report.Available != nil {
		t.Fatal("ownerless report invented capacity", report)
	}
}
