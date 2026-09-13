package controller

import (
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// setCertificateRequestCondition adds or updates one condition of a
// CertificateRequest, refreshing the transition time only when the status
// changes.
func setCertificateRequestCondition(cr *cmapi.CertificateRequest, conditionType cmapi.CertificateRequestConditionType, status cmmeta.ConditionStatus, reason, message string) {
	now := metav1.Now()
	for i := range cr.Status.Conditions {
		existing := &cr.Status.Conditions[i]
		if existing.Type != conditionType {
			continue
		}
		if existing.Status != status {
			existing.LastTransitionTime = &now
		}
		existing.Status = status
		existing.Reason = reason
		existing.Message = message
		return
	}

	cr.Status.Conditions = append(cr.Status.Conditions, cmapi.CertificateRequestCondition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: &now,
	})
}

// certificateRequestHasCondition reports whether a condition of the given type
// is set to the given status.
func certificateRequestHasCondition(cr *cmapi.CertificateRequest, conditionType cmapi.CertificateRequestConditionType, status cmmeta.ConditionStatus) bool {
	for _, condition := range cr.Status.Conditions {
		if condition.Type == conditionType {
			return condition.Status == status
		}
	}
	return false
}

// certificateRequestReadyReason returns the reason of the Ready condition, or
// the empty string when the condition is not set yet.
func certificateRequestReadyReason(cr *cmapi.CertificateRequest) string {
	for _, condition := range cr.Status.Conditions {
		if condition.Type == cmapi.CertificateRequestConditionReady {
			return condition.Reason
		}
	}
	return ""
}

// isApproved reports whether cert-manager approved the request.
func isApproved(cr *cmapi.CertificateRequest) bool {
	return certificateRequestHasCondition(cr, cmapi.CertificateRequestConditionApproved, cmmeta.ConditionTrue)
}

// isDenied reports whether cert-manager denied the request.
func isDenied(cr *cmapi.CertificateRequest) bool {
	return certificateRequestHasCondition(cr, cmapi.CertificateRequestConditionDenied, cmmeta.ConditionTrue)
}

// isFailed reports whether this controller already gave up on the request.
// cert-manager creates a replacement CertificateRequest rather than expecting a
// failed one to recover.
func isFailed(cr *cmapi.CertificateRequest) bool {
	return certificateRequestReadyReason(cr) == cmapi.CertificateRequestReasonFailed
}
