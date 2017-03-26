#include "config.h"

#include <epan/packet.h>
#include <stdbool.h>

#define LORAWAN_PORT 2404

static int proto_lorawan = -1;
static int hf_lorawan_mhdr = -1;
static int hf_lorawan_mic = -1;
static int hf_lorawan_devaddr = -1;
static int hf_lorawan_appeui = -1;
static int hf_lorawan_deveui = -1;
static int hf_lorawan_devnonce = -1;
static int hf_lorawan_appnonce = -1;
static int hf_lorawan_netid = -1;
static int hf_lorawan_dlsettings = -1;
static int hf_lorawan_rxdelay = -1;
static int hf_lorawan_fctrl = -1;
static int hf_lorawan_fcnt = -1;
static int hf_mhdr_mtype = -1;
static int hf_mhdr_rfu = -1;
static int hf_mhdr_major = -1;
static int hf_fctrl_adr = -1;
static int hf_fctrl_rfu6 = -1;
static int hf_fctrl_adrackreq = -1;
static int hf_fctrl_ack = -1;
static int hf_fctrl_fpending = -1;
static int hf_fctrl_rfu4 = -1;
static int hf_fctrl_foptslen = -1;
static int hf_lorawan_fopts = -1;
static int hf_fopts_foption = -1;
static int hf_dlfopt_CID = -1;
static int hf_ulfopt_CID = -1;
static int hf_lorawan_fport = -1;
static int hf_lorawan_frmpayload = -1;
static gint ett_lorawan = -1;
static gint ett_mhdr = -1;
static gint ett_fctrl = -1;
static gint ett_fopts = -1;

#define MTYPE(a, b, c) ((a << 2) | (b << 1) | (c << 0))

#define JOINREQUEST     MTYPE(0, 0, 0)
#define JOINACCEPT      MTYPE(0, 0, 1)
#define UNCONFUP        MTYPE(0, 1, 0)
#define UNCONFDOWN      MTYPE(0, 1, 1)
#define CONFUP          MTYPE(1, 0, 0)
#define CONFDOWN        MTYPE(1, 0, 1)
#define RFU             MTYPE(1, 1, 0)
#define PROP            MTYPE(1, 1, 1)

static value_string const mhdr_mtype[] = {
    {JOINREQUEST,   "Join Request"},
    {JOINACCEPT,    "Join Accept"},
    {UNCONFUP,      "Unconfirmed Data Up"},
    {UNCONFDOWN,    "Unconfirmed Data Down"},
    {CONFUP,        "Confirmed Data Up"},
    {CONFDOWN,      "Confirmed Data Down"},
    {RFU,           "Reserved for Future Usage"},
    {PROP,          "Proprietary"},
    {0,             NULL}
};

// uplink MAC commands
#define LINKCHECKREQ     0x02
#define LINKADRANS       0x03
#define DUTYCYCLEANS     0x04
#define RXPARAMSETUPANS  0x05
#define DEVSTATUSANS     0x06
#define NEWCHANNELANS    0x07
#define RXTIMINGSETUPANS 0x08
#define TXPARAMSETUPANS  0x09
#define DLCHANNELANS     0x0A

// size of MAC commands, including CID byte
// 0 means unknown
static guint8 const ul_command_length[] = {
    0, // 0 unknown
    0, // 1 unknown
    1, // LINKCHECKREQ     0x02
    2, // LINKADRANS       0x03
    1, // DUTYCYCLEANS     0x04
    2, // RXPARAMSETUPANS  0x05
    3, // DEVSTATUSANS     0x06
    2, // NEWCHANNELANS    0x07
    1, // RXTIMINGSETUPANS 0x08
    1, // TXPARAMSETUPANS  0x09
    2  // DLCHANNELANS     0x0A
};

// downlink MAC commands
#define LINKCHECKANS     0x02
#define LINKADRREQ       0x03
#define DUTYCYCLEREQ     0x04
#define RXPARAMSETUPREQ  0x05
#define DEVSTATUSREQ     0x06
#define NEWCHANNELREQ    0x07
#define RXTIMINGSETUPREQ 0x08
#define TXPARAMSETUPREQ  0x09
#define DLCHANNELREQ     0x0A

#define MAXKNOWNOPTION   0x0A

static guint8 const dl_command_length[] = {
    0, // 0 unknown
    0, // 1 unknown
    3, // LINKCHECKANS     0x02
    5, // LINKADRREQ       0x03
    2, // DUTYCYCLEREQ     0x04
    5, // RXPARAMSETUPREQ  0x05
    1, // DEVSTATUSREQ     0x06
    6, // NEWCHANNELREQ    0x07
    2, // RXTIMINGSETUPREQ 0x08
    2, // TXPARAMSETUPREQ  0x09
    5  // DLCHANNELREQ     0x0A
};

static value_string const dl_fopts_optiontype[] = {
    {LINKCHECKANS,      "LinkCheckAns"    },
    {LINKADRREQ,        "LinkADRReq"      },
    {DUTYCYCLEREQ,      "DutyCycleReq"    },
    {RXPARAMSETUPREQ,   "RxParamSetupReq" },
    {DEVSTATUSREQ,      "DevStatusReq"    },
    {NEWCHANNELREQ,     "NewChannelReq"   },
    {RXTIMINGSETUPREQ,  "RxTimingSetupReq"},
    {TXPARAMSETUPREQ,   "TxParamSetupReq" },
    {DLCHANNELREQ,      "DlChannelReq"    },
    {0,                 NULL}
};

static value_string const ul_fopts_optiontype[] = {
    {LINKCHECKREQ,      "LinkCheckReq"    },
    {LINKADRANS,        "LinkADRAns"      },
    {DUTYCYCLEANS,      "DutyCycleAns"    },
    {RXPARAMSETUPANS,   "RxParamSetupAns" },
    {DEVSTATUSANS,      "DevStatusAns"    },
    {NEWCHANNELANS,     "NewChannelAns"   },
    {RXTIMINGSETUPANS,  "RxTimingSetupAns"},
    {TXPARAMSETUPANS,   "TxParamSetupAns" },
    {DLCHANNELANS,      "DlChannelAns"    },
    {0,                 NULL}
};

#include <stdio.h>
/*static guint
dissect_lorawan_macpayload(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint8 fctrl, fctrl_foptslen;
    proto_item *fctrl_ti;
    proto_tree *fctrl_tree;

    proto_tree_add_item(tree, hf_lorawan_devaddr, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    fctrl = tvb_get_bits8(tvb, 8*offset, 8);
    fctrl_ti = proto_tree_add_item(tree, hf_lorawan_fctrl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    fctrl_tree = proto_item_add_subtree(fctrl_ti, ett_fctrl);
    proto_tree_add_item(fctrl_tree, hf_fctrl_adr, tvb, offset, 1, fctrl);
    proto_tree_add_item(fctrl_tree, hf_fctrl_adrackreq, tvb, offset, 1, fctrl);
    proto_tree_add_item(fctrl_tree, hf_fctrl_ack, tvb, offset, 1, fctrl);
    proto_tree_add_item(fctrl_tree, hf_fctrl_fpending, tvb, offset, 1, fctrl);
    proto_tree_add_item(fctrl_tree, hf_fctrl_foptslen, tvb, offset, 1, fctrl);
    offset += 1;

    proto_tree_add_item(tree, hf_lorawan_fcnt, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    fctrl_foptslen = fctrl & ((1 << 3) | (1 << 2) | (1 << 1) | (1 << 0));
    // TODO: Really dissect FOpts
    printf("fctrl: %08x, foptslen: %d\n", fctrl, fctrl_foptslen);
    proto_tree_add_item(tree, hf_fctrl_fopts, tvb, offset, fctrl_foptslen, ENC_NA);
    offset += fctrl_foptslen;

    proto_tree_add_item(tree, hf_lorawan_fport, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    proto_tree_add_item(tree, hf_lorawan_frmpayload, tvb, offset, tvb_reported_length(tvb) - offset - 4, ENC_NA);
    offset += tvb_reported_length(tvb) - offset - 4;

    return offset;
}
*/

/*static guint
dissect_lorawan_xxx(tvbuff_t *tvb, proto_tree *tree, guint offset)
{
    guint8 mhdr;
    proto_item *mhdr_ti;
    proto_tree *mhdr_tree;

    mhdr = tvb_get_bits8(tvb, offset, 8);
    mhdr_ti = proto_tree_add_item(tree, hf_lorawan_mhdr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    mhdr_tree = proto_item_add_subtree(mhdr_ti, ett_mhdr);
    proto_tree_add_item(mhdr_tree, hf_mhdr_mtype, tvb, offset, 1, mhdr);
    proto_tree_add_item(mhdr_tree, hf_mhdr_rfu, tvb, offset, 1, mhdr);
    proto_tree_add_item(mhdr_tree, hf_mhdr_major, tvb, offset, 1, mhdr);
    offset += 1;

    offset = dissect_lorawan_macpayload(tvb, tree, offset);

    proto_tree_add_item(tree, hf_lorawan_mic, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    return offset;
}
*/
static int
dissect_lorawan(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
        guint offset = 0;
        void * temp; // this avoids a compile warning
        temp = data; // same
        data = temp; // same

        col_set_str(pinfo->cinfo, COL_PROTOCOL, "LoRaWAN");
        col_clear(pinfo->cinfo, COL_INFO);


        proto_item *ti = proto_tree_add_item(tree, proto_lorawan, tvb, 0, -1, ENC_NA);
        proto_tree *lorawan_tree = proto_item_add_subtree(ti, ett_lorawan);
        

        // process Mac Header (MHDR)
        guint8 mhdr = tvb_get_bits8(tvb, 0, 3);
        proto_item *mhdr_ti;
        proto_tree *mhdr_tree;
        mhdr_ti = proto_tree_add_item(lorawan_tree, hf_lorawan_mhdr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        mhdr_tree = proto_item_add_subtree(mhdr_ti, ett_mhdr);
        proto_tree_add_item(mhdr_tree, hf_mhdr_mtype, tvb, offset, 1, mhdr);
        proto_tree_add_item(mhdr_tree, hf_mhdr_rfu, tvb, offset, 1, mhdr);
        proto_tree_add_item(mhdr_tree, hf_mhdr_major, tvb, offset, 1, mhdr);
        offset += 1;

        bool downlink_frame; // DL if true, UL if false
        if((mhdr & 1) == 1)  // odd-numbered Mtype frames happen to be all downlink, even-numbered uplink
        {                    // beware of RFU and proprietary, though!
            downlink_frame = true;
        }
        else
        {
            downlink_frame = false;
        }       

        switch (mhdr) {
        // Join messages
        case JOINREQUEST : 
            proto_tree_add_item(lorawan_tree, hf_lorawan_appeui, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(lorawan_tree, hf_lorawan_deveui, tvb, offset, 8, ENC_LITTLE_ENDIAN);
            offset += 8;
            proto_tree_add_item(lorawan_tree, hf_lorawan_devnonce, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            break;
        case JOINACCEPT : 
            proto_tree_add_item(lorawan_tree, hf_lorawan_appnonce, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            offset += 3;
            proto_tree_add_item(lorawan_tree, hf_lorawan_netid, tvb, offset, 3, ENC_LITTLE_ENDIAN);
            offset += 3;
            proto_tree_add_item(lorawan_tree, hf_lorawan_devaddr, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(lorawan_tree, hf_lorawan_dlsettings, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(lorawan_tree, hf_lorawan_rxdelay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            break;
        // Data messages
        case UNCONFUP : 
        case UNCONFDOWN : 
        case CONFUP : 
        case CONFDOWN : 
            // process Frame Header (FHDR)
            proto_tree_add_item(lorawan_tree, hf_lorawan_devaddr, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_item *fctrl_ti;
            fctrl_ti = proto_tree_add_item(lorawan_tree, hf_lorawan_fctrl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            proto_tree *fctrl_tree;
            fctrl_tree = proto_item_add_subtree(fctrl_ti, ett_fctrl);
            if(downlink_frame == true)
            {
                proto_tree_add_item(fctrl_tree, hf_fctrl_adr, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(fctrl_tree, hf_fctrl_rfu6, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(fctrl_tree, hf_fctrl_ack, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(fctrl_tree, hf_fctrl_fpending, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(fctrl_tree, hf_fctrl_foptslen, tvb, offset, 1, ENC_NA);    
            }
            else
            {
                proto_tree_add_item(fctrl_tree, hf_fctrl_adr, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(fctrl_tree, hf_fctrl_adrackreq, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(fctrl_tree, hf_fctrl_ack, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(fctrl_tree, hf_fctrl_rfu4, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(fctrl_tree, hf_fctrl_foptslen, tvb, offset, 1, ENC_NA);
            }
            guint8 foptslen;
            foptslen = tvb_get_bits8(tvb, offset*8 + 4, 4);
            offset += 1;
            proto_tree_add_item(lorawan_tree, hf_lorawan_fcnt, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            // process 0 to 15 bytes of Frame Options (FOpts)
            if (foptslen > 0) {
                printf ("foptslen = %d\n", foptslen);
                proto_item *opts_item;
                opts_item = proto_tree_add_item(lorawan_tree, hf_lorawan_fopts, tvb, offset, foptslen, ENC_NA);
                proto_tree *opts_tree;
                opts_tree = proto_item_add_subtree(opts_item, ett_fopts);
                guint8 option1;
                option1 = tvb_get_guint8(tvb, offset);
                guint8 option1_length;
                option1_length = (downlink_frame ? dl_command_length[option1] : ul_command_length[option1]);
                proto_item *opt1_ti;
                opt1_ti = proto_tree_add_item(opts_tree, hf_fopts_foption, tvb, offset, option1_length, ENC_NA);
                proto_tree *opt1_tree;
                opt1_tree = proto_item_add_subtree(opt1_ti, ett_fopts);
                if (downlink_frame) {
                    proto_tree_add_item(opt1_tree, hf_dlfopt_CID, tvb, offset, 1, ENC_NA);
                }
                else {
                    proto_tree_add_item(opt1_tree, hf_ulfopt_CID, tvb, offset, 1, ENC_NA);                    
                }
                offset += option1_length;
            }
            // if payload not empty, 1 byte of FPort and variable number of bytes of actual payload
            ;
            break;
        case PROP : 
            break;
        case RFU : 
            break;
        default:
            // all possible cases are covered, one should never reach default
            break;
        }

       return tvb_captured_length(tvb);

}

/*
static int
dissect_lorawan(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    void * temp;
    temp = data;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LoRaWAN");
    col_clear(pinfo->cinfo, COL_INFO);
    guint offset = 0;

    if (tree) {
        proto_item *ti = NULL;
        proto_tree *lorawan_tree = NULL;

        ti = proto_tree_add_item(tree, proto_lorawan, tvb, 0, -1, ENC_NA);
        lorawan_tree = proto_item_add_subtree(ti, ett_lorawan);

        guint8 mhdr;
        proto_item *mhdr_ti;
        proto_tree *mhdr_tree;

        mhdr = tvb_get_bits8(tvb, offset, 8);
        mhdr = 0x55;
        mhdr_ti = proto_tree_add_item(tree, hf_lorawan_mhdr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        mhdr_tree = proto_item_add_subtree(mhdr_ti, ett_mhdr);
        hf_mhdr_mtype = 0xFF;
        proto_tree_add_item(mhdr_tree, hf_mhdr_mtype, tvb, offset, 1, mhdr);
        printf("mhdr.mtype %d %x\n", hf_mhdr_mtype, mhdr);
        proto_tree_add_item(mhdr_tree, hf_mhdr_rfu, tvb, offset, 1, mhdr);
        proto_tree_add_item(mhdr_tree, hf_mhdr_major, tvb, offset, 1, mhdr);
        offset += 1;

        switch (0) {
            case 1 : 
                break;
            default:
            //TODO: how do I declare that the event is not recognized? Expert field? To investigate 
            break;
        }
//    offset = dissect_lorawan_macpayload(tvb, tree, offset);
        guint8 fctrl, fctrl_foptslen;
        proto_item *fctrl_ti;
        proto_tree *fctrl_tree;

        proto_tree_add_item(tree, hf_lorawan_devaddr, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        fctrl = tvb_get_bits8(tvb, 8*offset, 8);
        fctrl_ti = proto_tree_add_item(tree, hf_lorawan_fctrl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        fctrl_tree = proto_item_add_subtree(fctrl_ti, ett_fctrl);
        proto_tree_add_item(fctrl_tree, hf_fctrl_adr, tvb, offset, 1, fctrl);
        proto_tree_add_item(fctrl_tree, hf_fctrl_adrackreq, tvb, offset, 1, fctrl);
        proto_tree_add_item(fctrl_tree, hf_fctrl_ack, tvb, offset, 1, fctrl);
        proto_tree_add_item(fctrl_tree, hf_fctrl_fpending, tvb, offset, 1, fctrl);
        proto_tree_add_item(fctrl_tree, hf_fctrl_foptslen, tvb, offset, 1, fctrl);
        offset += 1;

        proto_tree_add_item(tree, hf_lorawan_fcnt, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        fctrl_foptslen = fctrl & ((1 << 3) | (1 << 2) | (1 << 1) | (1 << 0));
        // TODO: Really dissect FOpts 
        printf("fctrl: %08x, foptslen: %d\n", fctrl, fctrl_foptslen);
        proto_tree_add_item(tree, hf_fctrl_fopts, tvb, offset, fctrl_foptslen, ENC_NA);
        offset += fctrl_foptslen;

        proto_tree_add_item(tree, hf_lorawan_fport, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        proto_tree_add_item(tree, hf_lorawan_frmpayload, tvb, offset, tvb_reported_length(tvb) - offset - 4, ENC_NA);
        offset += tvb_reported_length(tvb) - offset - 4;


        proto_tree_add_item(tree, hf_lorawan_mic, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

    }

    return tvb_captured_length(tvb);
}

*/
void
proto_register_lorawan(void)
{
    static hf_register_info hf[] = {
        { &hf_lorawan_mhdr, { "MHDR", "lorawan.mhdr", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lorawan_mic, { "MIC", "lorawan.mic", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lorawan_appeui, { "AppEUI", "lorawan.appeui", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lorawan_deveui, { "DevEUI", "lorawan.deveui", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lorawan_devaddr, { "DevAddr", "lorawan.devaddr", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lorawan_dlsettings, { "DLSettings", "lorawan.dlsettings", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lorawan_devnonce, { "DevNonce", "lorawan.devnonce", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lorawan_appnonce, { "AppNonce", "lorawan.appnonce", FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lorawan_netid, { "NetID", "lorawan.netid", FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lorawan_rxdelay, { "RxDelay", "lorawan.rxdelay", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lorawan_fctrl, { "FCtrl", "lorawan.fctrl", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lorawan_fcnt, { "FCnt", "lorawan.fcnt", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_mhdr_mtype, { "MType", "lorawan.mhdr.mtype", FT_UINT8, BASE_HEX, VALS(&mhdr_mtype), (1 << 7) | (1 << 6) | (1 << 5), NULL, HFILL }},
        { &hf_mhdr_rfu, { "Reserved", "lorawan.mhdr.rfu", FT_BOOLEAN, 8, TFS(&tfs_set_notset), (1 << 4) | (1 << 3) | (1 << 2), NULL, HFILL }},
        { &hf_mhdr_major, { "Major", "lorawan.mhdr.major", FT_UINT8, BASE_DEC, NULL, (1 << 1) | (1 << 0), NULL, HFILL }},
        { &hf_fctrl_adr, { "ADR (Adaptative Data Rate)", "lorawan.fctrl.adr", FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), (1 << 7), NULL, HFILL }},
        { &hf_fctrl_adrackreq, { "ADRACKReq", "lorawan.fctrl.adrackreq", FT_BOOLEAN, 8, TFS(&tfs_set_notset), (1 << 6), NULL, HFILL }},
        { &hf_fctrl_rfu6, { "RFU", "lorawan.fctrl.rfu6", FT_BOOLEAN, 8, TFS(&tfs_set_notset), (1 << 6), NULL, HFILL }},
        { &hf_fctrl_ack, { "ACK", "lorawan.fctrl.ack", FT_BOOLEAN, 8, TFS(&tfs_ack_nack), (1 << 5), NULL, HFILL }},
        { &hf_fctrl_rfu4, { "RFU", "lorawan.fctrl.rfu4", FT_BOOLEAN, 8, TFS(&tfs_set_notset), (1 << 4), NULL, HFILL }},
        { &hf_fctrl_fpending, { "FPending", "lorawan.fctrl.fpending", FT_BOOLEAN, 8, TFS(&tfs_set_notset), (1 << 4), NULL, HFILL }},
        { &hf_fctrl_foptslen, { "FOptsLen", "lorawan.fctrl.foptslen", FT_UINT8, BASE_DEC, NULL, (1 << 3) | (1 << 2) | (1 << 1) | (1 << 0), NULL, HFILL, }},
        { &hf_lorawan_fopts, { "FOpts", "lorawan.fopts", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_fopts_foption, { "FOption", "lorawan.fopts.foption", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
        { &hf_dlfopt_CID, { "CID", "lorawan.fopts.foption.CID", FT_UINT8, BASE_HEX, VALS(&dl_fopts_optiontype), 0x00, NULL, HFILL }},
        { &hf_ulfopt_CID, { "CID", "lorawan.fopts.foption.CID", FT_UINT8, BASE_HEX, VALS(&ul_fopts_optiontype), 0x00, NULL, HFILL }},
        { &hf_lorawan_fport, { "FPort", "lorawan.fport", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
        { &hf_lorawan_frmpayload, { "FRMPayload", "lorawan.frmpayload", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }}
    };

    static gint *ett[] = {
        &ett_lorawan,
        &ett_mhdr,
        &ett_fctrl,
        &ett_fopts
    };

    proto_lorawan = proto_register_protocol(
        "LoRaWAN 1.0.2",
        "lorawan",
        "lorawan"
    );

    proto_register_field_array(proto_lorawan, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    
    /*  Register dissectors with Wireshark. */
    register_dissector("lorawan", (dissector_t) dissect_lorawan, proto_lorawan);
    }

void
proto_reg_handoff_lorawan(void)
{
//    static dissector_handle_t lorawan_handle;

//    lorawan_handle = create_dissector_handle(dissect_lorawan, proto_lorawan);
//    dissector_add_uint("sensorlab.eventID", 0x34, lorawan_handle);
//    dissector_add_uint("104asdu.addr", 1, lorawan_handle);
//    dissector_add_uint("104asdu.addr", 10, lorawan_handle);
}
