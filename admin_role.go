package main

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	// "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func check_admin_role() bool {
	adminRoleInput := iam.GetRoleInput{
		RoleName: aws.String(admin_role_name),
	}

	_, err := IAMClient.GetRole(context.TODO(), &adminRoleInput)
	if err != nil {
		//fmt.Println("nil arn, creating role")
		if strings.Contains(err.Error(), "NoSuchEntity: The role with name") {
			fmt.Printf("role %s not found, creating", admin_role_name)
		} else {
			log.Fatal(err)
		}
	} else {
		return true
	}

	return false
}

func create_admin_role() {
	fmt.Println("creating admin role")
	result, err := IAMClient.CreateRole(context.TODO(), &iam.CreateRoleInput{
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
        }
`),
	})

	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Printf("%v", result)

	_, attachErr := IAMClient.AttachRolePolicy(context.TODO(), &iam.AttachRolePolicyInput{
		RoleName:  aws.String(admin_role_name),
		PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess"),
	})

	if attachErr != nil {
		log.Fatalln(attachErr.Error())
	}

}
