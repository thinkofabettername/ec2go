package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func resizeDiskModule() {
	fmt.Println("Select instance which requires disk resizing")
	instances := listInstances()
	var instanceToResizeDisk int
	fmt.Scan(&instanceToResizeDisk)

	fmt.Println("resizing ", instanceToResizeDisk)
	volumeId := *instances.Reservations[instanceToResizeDisk].Instances[0].BlockDeviceMappings[0].Ebs.VolumeId

	volType := ""
	var iops int32 = 5000
	var throughput int32 = 200
	var size int32 = 100

	fmt.Print("New volume type (gp2,gp3,io,st1,sc1)\n or press enter for gp3,5000IOPS,200MB/s,100GB:")
	fmt.Scanln(&volType)

	if volType == "gp2" {
		fmt.Print("Size GB:")
		fmt.Scan(&size)
	} else if volType == "io2" || volType == "io1" {
		fmt.Print("IOPs:")
		fmt.Scan(&iops)
		fmt.Print("Size GB:")
		fmt.Scan(&size)
	} else if volType != "" {
		fmt.Print("IOPs:")
		fmt.Scan(&iops)
		fmt.Print("Throughput MB/s:")
		fmt.Scan(&throughput)
		fmt.Print("Size GB:")
		fmt.Scan(&size)
	}

	if volType == "" {
		volType = "gp3"
	}

	println(volumeId)

	if volType == "gp2" {
		_, err := client.ModifyVolume(context.TODO(), &ec2.ModifyVolumeInput{
			VolumeId:   &volumeId,
			VolumeType: types.VolumeType(volType),
			Size:       aws.Int32(size),
		})
		if err != nil {
			fmt.Println("Error Resizing volume, ", err)
		}
	} else if volType == "io1" || volType == "io2" {
		_, err := client.ModifyVolume(context.TODO(), &ec2.ModifyVolumeInput{
			VolumeId:   &volumeId,
			VolumeType: types.VolumeType(volType),
			Iops:       aws.Int32(iops),
			Size:       aws.Int32(size),
		})
		if err != nil {
			fmt.Println("Error Resizing volume, ", err)
		}

	} else {
		_, err := client.ModifyVolume(context.TODO(), &ec2.ModifyVolumeInput{
			VolumeId:   &volumeId,
			VolumeType: types.VolumeType(volType),
			Iops:       aws.Int32(iops),
			Throughput: aws.Int32(throughput),
			Size:       aws.Int32(size),
		})
		if err != nil {
			fmt.Println("Error Resizing volume, ", err)
		}
	}
}
