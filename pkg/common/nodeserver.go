package common

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/kubernetes-sigs/alibaba-cloud-csi-driver/pkg/metric"
	"github.com/kubernetes-sigs/alibaba-cloud-csi-driver/pkg/utils"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

func WrapNodeServerWithMetricRecorder(server csi.NodeServer, driverType string, client kubernetes.Interface) csi.NodeServer {
	return &NodeServerWithMetricRecorder{
		NodeServer: server,
		driverType: driverType,
		client:     client,
	}
}

type NodeServerWithMetricRecorder struct {
	csi.NodeServer
	driverType string
	client     kubernetes.Interface
}

func (s *NodeServerWithMetricRecorder) NodePublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	ctx = withPodInfo(ctx, s.client, req)
	resp, err := s.NodeServer.NodePublishVolume(ctx, req)
	s.recordVolumeAttachmentTime(ctx, req, err)
	return resp, err
}

func withPodInfo(ctx context.Context, client kubernetes.Interface, req *csi.NodePublishVolumeRequest) context.Context {
	name, namespace := req.VolumeContext[podNameKey], req.VolumeContext[podNamespaceKey]
	if name == "" || namespace == "" {
		klog.Warningf("withPodInfo: empty pod name/namespace: %s, %s", name, namespace)
		return ctx
	}
	pod, err := client.CoreV1().Pods(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		klog.Warningf("withPodInfo: error getting pod %s/%s when recording attachment time of volume %s", namespace, name, req.GetVolumeId())
		return ctx
	}
	return context.WithValue(ctx, utils.PodInfo, pod)
}

func (s *NodeServerWithMetricRecorder) recordVolumeAttachmentTime(ctx context.Context, req *csi.NodePublishVolumeRequest, err error) {
	name, namespace := req.VolumeContext[podNameKey], req.VolumeContext[podNamespaceKey]
	if name == "" || namespace == "" {
		klog.Warningf("recordVolumeAttachmentTime: empty pod name/namespace: %s, %s", name, namespace)
		return
	}
	pod, err := utils.GetPodFromContextOrK8s(ctx, s.client, namespace, name)
	if err != nil {
		klog.Errorf("recordVolumeAttachmentTime: volume %s: error getting pod info from context", req.GetVolumeId())
		return
	}
	podStartTime, err := getPodStartTime(pod)
	if err != nil {
		klog.Errorf("recordVolumeAttachmentTime: volume %s: error getting scheduled time for pod %s/%s", pod.GetNamespace(), pod.GetName(), req.GetVolumeId())
		return
	}

	labels := prometheus.Labels{
		metric.VolumeStatsLabelType: s.driverType,
		metric.VolumeStatsLabelCode: status.Code(err).String(),
	}
	metric.VolumeStatCollector.AttachmentCountMetric.With(labels).Inc()
	metric.VolumeStatCollector.AttachmentTimeTotalMetric.With(labels).Add(float64(time.Since(podStartTime).Seconds()))
}

func getPodStartTime(pod *v1.Pod) (time.Time, error) {
	startTime := pod.Status.StartTime
	if startTime == nil {
		return time.Time{}, fmt.Errorf("getPodStartTime: no start time found for pod %s/%s ", pod.GetNamespace(), pod.GetName())
	}
	return startTime.Time, nil
}

func WrapNodeServerWithValidator(server csi.NodeServer) csi.NodeServer {
	return &NodeServerWithValidator{NodeServer: server}
}

type NodeServerWithValidator struct {
	csi.NodeServer
}

func (s *NodeServerWithValidator) NodeStageVolume(ctx context.Context, req *csi.NodeStageVolumeRequest) (*csi.NodeStageVolumeResponse, error) {
	if len(req.VolumeId) == 0 {
		return nil, status.Error(codes.InvalidArgument, "VolumeId is required")
	}
	if req.VolumeCapability == nil {
		return nil, status.Error(codes.InvalidArgument, "VolumeCapability is required")
	}
	if len(req.StagingTargetPath) == 0 {
		return nil, status.Error(codes.InvalidArgument, "StagingTargetPath is required")
	}
	ok, err := filepathContains(utils.KubeletRootDir, req.StagingTargetPath)
	if err != nil || !ok {
		return nil, status.Errorf(codes.InvalidArgument, "Staging path %q is not a subpath of %s", req.StagingTargetPath, utils.KubeletRootDir)
	}
	return s.NodeServer.NodeStageVolume(ctx, req)
}

func (s *NodeServerWithValidator) NodePublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	if len(req.VolumeId) == 0 {
		return nil, status.Error(codes.InvalidArgument, "VolumeId is required")
	}
	if req.VolumeCapability == nil {
		return nil, status.Error(codes.InvalidArgument, "VolumeCapability is required")
	}
	if len(req.TargetPath) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "TargetPath is required")
	}
	ok, err := filepathContains(utils.KubeletRootDir, req.TargetPath)
	if err != nil || !ok {
		return nil, status.Errorf(codes.InvalidArgument, "Target path %q is not a subpath of %s", req.TargetPath, utils.KubeletRootDir)
	}
	return s.NodeServer.NodePublishVolume(ctx, req)
}

func (s *NodeServerWithValidator) NodeUnstageVolume(context context.Context, req *csi.NodeUnstageVolumeRequest) (*csi.NodeUnstageVolumeResponse, error) {
	if len(req.VolumeId) == 0 {
		return nil, status.Error(codes.InvalidArgument, "VolumeId is required")
	}
	if len(req.StagingTargetPath) == 0 {
		return nil, status.Error(codes.InvalidArgument, "StagingTargetPath is required")
	}
	return s.NodeServer.NodeUnstageVolume(context, req)
}

func (s *NodeServerWithValidator) NodeUnpublishVolume(context context.Context, req *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {
	if len(req.VolumeId) == 0 {
		return nil, status.Error(codes.InvalidArgument, "VolumeId is required")
	}
	if len(req.TargetPath) == 0 {
		return nil, status.Error(codes.InvalidArgument, "TargetPath is required")
	}
	return s.NodeServer.NodeUnpublishVolume(context, req)
}

func (s *NodeServerWithValidator) NodeGetVolumeStats(context context.Context, req *csi.NodeGetVolumeStatsRequest) (*csi.NodeGetVolumeStatsResponse, error) {
	if len(req.VolumeId) == 0 {
		return nil, status.Error(codes.InvalidArgument, "VolumeId is required")
	}
	if len(req.VolumePath) == 0 {
		return nil, status.Error(codes.InvalidArgument, "VolumePath is required")
	}
	return s.NodeServer.NodeGetVolumeStats(context, req)
}

func (s *NodeServerWithValidator) NodeExpandVolume(context context.Context, req *csi.NodeExpandVolumeRequest) (*csi.NodeExpandVolumeResponse, error) {
	if len(req.VolumeId) == 0 {
		return nil, status.Error(codes.InvalidArgument, "VolumeId is required")
	}
	if len(req.VolumePath) == 0 {
		return nil, status.Error(codes.InvalidArgument, "VolumePath is required")
	}
	return s.NodeServer.NodeExpandVolume(context, req)
}

func filepathContains(basePath, path string) (bool, error) {
	relPath, err := filepath.Rel(basePath, path)
	if err != nil {
		return false, err
	}
	return !strings.HasPrefix(relPath, ".."+string(os.PathSeparator)), nil
}

type GenericNodeServer struct {
	csi.UnimplementedNodeServer
	NodeID string
}

func (ns *GenericNodeServer) NodeGetInfo(ctx context.Context, req *csi.NodeGetInfoRequest) (*csi.NodeGetInfoResponse, error) {
	return &csi.NodeGetInfoResponse{
		NodeId: ns.NodeID,
	}, nil
}

func (ns *GenericNodeServer) NodeGetCapabilities(context context.Context, req *csi.NodeGetCapabilitiesRequest) (*csi.NodeGetCapabilitiesResponse, error) {
	return &csi.NodeGetCapabilitiesResponse{}, nil
}

func (*GenericNodeServer) NodeGetVolumeStats(ctx context.Context, req *csi.NodeGetVolumeStatsRequest) (*csi.NodeGetVolumeStatsResponse, error) {
	resp, err := utils.GetMetrics(req.VolumePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, status.Errorf(codes.NotFound, "VolumePath %s not found: %v", req.VolumePath, err)
	}
	return resp, err
}
