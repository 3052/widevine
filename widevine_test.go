package widevine

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"testing"
)

// therokuchannel.roku.com/watch/597a64a4a25c5bf6af4a8c7053049a6f
const post_pssh = "AAAAQ3Bzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAACMIARIQKDOa149zRSDaJObgVz05LhoKaW50ZXJ0cnVzdCIBKg=="

func (roku) _Request_URL() string {
	return "https://wv-license.sr.roku.com/license/v1/license/wv?token=Lc1ODa8rmoLJIqcK_qX5Qx6AVI1Ukeh20aUY13fyTZkMNDilufUl_UvdF_tcakp6teHDb5yBYZVjsXIt-Gadl_bOJVzEFIhNZCMSYh7aO0KM9HrY2G-mfm3sHQLEUulP5Cd3a2TNFZdJV2Xv5_TnOIJpyU1jTuDs16uvOkRvsJ6luRagJR0y-J-EJmocwUH4WrRZ8lFrzMQ2u3-AGrN_vFtGgx390fhQp7tLH4ImInykc6MtASyTpO0XOD1BvIC6_aF5ghOux3OOTTj_XXadIDT74Fo6NbFZ8gXzwcSSNbT_830Kz4Sdqmpevk2lytcuF2E46KYh56YvjpAu5YkZp04fVAOv_xYajw==&traceId=8dd3b05b934e8b215d86d3d8fce8e430&ExpressPlayToken=none"
}

func (roku) _Request_Header() http.Header {
	return nil
}

func (roku) Encode_Request(b []byte) ([]byte, error) {
	return b, nil
}

func (roku) Decode_Response(b []byte) ([]byte, error) {
	return b, nil
}

type roku struct{}

func Test_Post(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	private_key, err := os.ReadFile(home + "/widevine/private_key.pem")
	if err != nil {
		t.Fatal(err)
	}
	client_ID, err := os.ReadFile(home + "/widevine/client_id.bin")
	if err != nil {
		t.Fatal(err)
	}
	pssh, err := base64.StdEncoding.DecodeString(post_pssh)
	if err != nil {
		t.Fatal(err)
	}
	mod, err := _New_Module(private_key, client_ID, pssh)
	if err != nil {
		t.Fatal(err)
	}
	key, err := mod.Post(roku{})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%x\n", key)
}
