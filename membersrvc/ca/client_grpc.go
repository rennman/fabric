package ca

import (
	pb "github.com/hyperledger/fabric/membersrvc/protos"
	"google.golang.org/grpc"
  "fmt"
	"github.com/spf13/viper"
	"io/ioutil"
	"crypto/tls"
	"crypto/x509"
	"google.golang.org/grpc/credentials"
	"time"


)

func NewClientTLSFromFile(certFile, serverNameOverride string) (credentials.TransportCredentials, error) {
    caLogger.Info("upgrading to TLS1.2")
    b, err := ioutil.ReadFile(certFile)

    if err != nil {
        return nil, err
    }
    cp := x509.NewCertPool()

    ok := cp.AppendCertsFromPEM(b)
		if !ok {
        return nil, fmt.Errorf("credentials: failed to append certificates: ", ok)
    }
    return credentials.NewTLS(&tls.Config{ServerName: serverNameOverride, RootCAs: cp , MinVersion : 0 , MaxVersion : 0 }), nil
}
//GetClientConn returns a connection to the server located on *address*.
func GetClientConn(address string, serverName string) (*grpc.ClientConn, error) {

	caLogger.Info("inside GetClientConn")
	var opts []grpc.DialOption

	if viper.GetBool("security.tls_enabled"){

	  creds, err := NewClientTLSFromFile(viper.GetString("security.client.cert.file"), viper.GetString("security.serverhostoverride"))

		if err != nil{
			//fmt.Println("error in GetClientConn while getting creds: ", err)
			caLogger.Info("error in GetClientConn while getting creds:")
			caLogger.Panic()
			return nil, err
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
 } else {
	   opts = append(opts, grpc.WithInsecure())
	 }
	 opts = append(opts, grpc.WithTimeout(time.Second*3))
   return grpc.Dial(address, opts...)
}

//GetACAClient returns a client to Attribute Certificate Authority.
func GetACAClient() (*grpc.ClientConn, pb.ACAPClient, error) {
	caLogger.Info("inside GetACAClient")
	conn, err := GetClientConn(viper.GetString("aca.address"), viper.GetString("aca.server-name"))
	if err != nil {
		return nil, nil, err
	}

	client := pb.NewACAPClient(conn)

	return conn, client, nil
}
