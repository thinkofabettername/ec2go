package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	// "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func assign_role_to_instance(instanceId string) {
	if !check_admin_role() {
		create_admin_role()
	}

	profileSpec := types.IamInstanceProfileSpecification{
		Name: &admin_role_name,
	}

	_, err := client.AssociateIamInstanceProfile(context.TODO(), &ec2.AssociateIamInstanceProfileInput{
		IamInstanceProfile: &profileSpec,
		InstanceId:         aws.String(instanceId),
	})

	if err != nil {
		log.Fatalln(err.Error())
	}
}

func check_admin_role() bool {
	adminRoleInput := iam.GetInstanceProfileInput{
		InstanceProfileName: aws.String(admin_role_name),
	}

	_, err := IAMClient.GetInstanceProfile(context.TODO(), &adminRoleInput)
	if err != nil {
		//fmt.Println("nil arn, creating role")
		if strings.Contains(err.Error(), "NoSuchEntity: Instance Profile") {
			fmt.Printf("role %s not found, creating\n", admin_role_name)
		} else {
			log.Fatal(err)
		}
	} else {
		return true
	}

	return false
}

func create_admin_role() {
	sleeptime := 2
	fmt.Println("creating admin role")
	profile_result, profile_err := IAMClient.CreateInstanceProfile(context.TODO(), &iam.CreateInstanceProfileInput{
		InstanceProfileName: &admin_role_name,
	})

	fmt.Printf("sleeping for %d seconds to wait for the cloud to catch up ", sleeptime)
	time.Sleep(time.Duration(sleeptime))

	if profile_err != nil {
		fmt.Println(profile_err.Error())
		//exit()
	}

	role_result, role_err := IAMClient.CreateRole(context.TODO(), &iam.CreateRoleInput{
		RoleName: &admin_role_name,
		AssumeRolePolicyDocument: aws.String(`{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
} `),
	})

	fmt.Printf("sleeping for %d seconds to wait for the cloud to catch up ", sleeptime)
	time.Sleep(time.Duration(sleeptime))

	if role_err != nil {
		fmt.Println(role_err.Error())
	}

	role_profile_result, role_profile_err := IAMClient.AddRoleToInstanceProfile(context.TODO(), &iam.AddRoleToInstanceProfileInput{
		InstanceProfileName: aws.String(admin_role_name),
		RoleName:            aws.String(admin_role_name),
	})

	fmt.Printf("sleeping for %d seconds to wait for the cloud to catch up ", sleeptime)
	time.Sleep(time.Duration(sleeptime))

	if role_profile_err != nil {
		fmt.Println((role_profile_err.Error()))
	}

	fmt.Printf("%v", *profile_result)
	fmt.Printf("%v", *role_result)
	fmt.Printf("%v", *role_profile_result)

	_, attachErr := IAMClient.AttachRolePolicy(context.TODO(), &iam.AttachRolePolicyInput{
		RoleName:  aws.String(admin_role_name),
		PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess"),
	})

	fmt.Printf("sleeping for %d seconds to wait for the cloud to catch up ", sleeptime)
	time.Sleep(time.Duration(sleeptime))

	if attachErr != nil {
		log.Fatalln(attachErr.Error())
	}

}
