package nas

//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.
//
// Code generated by Alibaba Cloud SDK Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

import (
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/responses"
)

// ListRecycleBinJobs invokes the nas.ListRecycleBinJobs API synchronously
func (client *Client) ListRecycleBinJobs(request *ListRecycleBinJobsRequest) (response *ListRecycleBinJobsResponse, err error) {
	response = CreateListRecycleBinJobsResponse()
	err = client.DoAction(request, response)
	return
}

// ListRecycleBinJobsWithChan invokes the nas.ListRecycleBinJobs API asynchronously
func (client *Client) ListRecycleBinJobsWithChan(request *ListRecycleBinJobsRequest) (<-chan *ListRecycleBinJobsResponse, <-chan error) {
	responseChan := make(chan *ListRecycleBinJobsResponse, 1)
	errChan := make(chan error, 1)
	err := client.AddAsyncTask(func() {
		defer close(responseChan)
		defer close(errChan)
		response, err := client.ListRecycleBinJobs(request)
		if err != nil {
			errChan <- err
		} else {
			responseChan <- response
		}
	})
	if err != nil {
		errChan <- err
		close(responseChan)
		close(errChan)
	}
	return responseChan, errChan
}

// ListRecycleBinJobsWithCallback invokes the nas.ListRecycleBinJobs API asynchronously
func (client *Client) ListRecycleBinJobsWithCallback(request *ListRecycleBinJobsRequest, callback func(response *ListRecycleBinJobsResponse, err error)) <-chan int {
	result := make(chan int, 1)
	err := client.AddAsyncTask(func() {
		var response *ListRecycleBinJobsResponse
		var err error
		defer close(result)
		response, err = client.ListRecycleBinJobs(request)
		callback(response, err)
		result <- 1
	})
	if err != nil {
		defer close(result)
		callback(nil, err)
		result <- 0
	}
	return result
}

// ListRecycleBinJobsRequest is the request struct for api ListRecycleBinJobs
type ListRecycleBinJobsRequest struct {
	*requests.RpcRequest
	PageNumber   requests.Integer `position:"Query" name:"PageNumber"`
	JobId        string           `position:"Query" name:"JobId"`
	PageSize     requests.Integer `position:"Query" name:"PageSize"`
	FileSystemId string           `position:"Query" name:"FileSystemId"`
	Status       string           `position:"Query" name:"Status"`
}

// ListRecycleBinJobsResponse is the response struct for api ListRecycleBinJobs
type ListRecycleBinJobsResponse struct {
	*responses.BaseResponse
	RequestId  string `json:"RequestId" xml:"RequestId"`
	TotalCount int64  `json:"TotalCount" xml:"TotalCount"`
	PageNumber int64  `json:"PageNumber" xml:"PageNumber"`
	PageSize   int64  `json:"PageSize" xml:"PageSize"`
	Jobs       []Job  `json:"Jobs" xml:"Jobs"`
}

// CreateListRecycleBinJobsRequest creates a request to invoke ListRecycleBinJobs API
func CreateListRecycleBinJobsRequest() (request *ListRecycleBinJobsRequest) {
	request = &ListRecycleBinJobsRequest{
		RpcRequest: &requests.RpcRequest{},
	}
	request.InitWithApiInfo("NAS", "2017-06-26", "ListRecycleBinJobs", "", "")
	request.Method = requests.GET
	return
}

// CreateListRecycleBinJobsResponse creates a response to parse from ListRecycleBinJobs response
func CreateListRecycleBinJobsResponse() (response *ListRecycleBinJobsResponse) {
	response = &ListRecycleBinJobsResponse{
		BaseResponse: &responses.BaseResponse{},
	}
	return
}