
/*
 * Retroshare Photo Plugin.
 *
 * Copyright 2012-2012 by Robert Fernie.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License Version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA.
 *
 * Please report all bugs and problems to "retroshare@lunamutt.com".
 *
 */

#include "PhotoShare.h"
#include "ui_PhotoShare.h"

#include <retroshare/rspeers.h>
#include <retroshare/rsphoto.h>
#include <retroshare/rsgxsflags.h>

#include <iostream>
#include <sstream>

#include <QTimer>
#include <QMessageBox>

#include "AlbumCreateDialog.h"
#include "AlbumItem.h"
#include "PhotoItem.h"

/******
 * #define PHOTO_DEBUG 1
 *****/


/****************************************************************
 * New Photo Display Widget.
 *
 * This has two 'lists'.
 * Top list shows Albums.
 * Lower list is photos from the selected Album.
 *
 * Notes:
 *   Each Item will be an AlbumItem, which contains a thumbnail & random details.
 *   We will limit Items to < 100. With a 'Filter to see more message.
 *
 *   Thumbnails will come from Service.
 *   Option to Share albums / pictures onward (if permissions allow).
 *   Option to Download the albums to a specified directory. (is this required if sharing an album?)
 *
 *   Will introduce a FullScreen SlideShow later... first get basics happening.
 */

#define IS_ALBUM_ADMIN(subscribeFlags) (subscribeFlags & GXS_SERV::GROUP_SUBSCRIBE_ADMIN)
#define IS_ALBUM_SUBSCRIBED(subscribeFlags) (subscribeFlags & GXS_SERV::GROUP_SUBSCRIBE_SUBSCRIBED)
#define IS_ALBUM_N_SUBSCR_OR_ADMIN(subscribeFlags) ((subscribeFlags & GXS_SERV::GROUP_SUBSCRIBE_MASK) == 0)


/** Constructor */
PhotoShare::PhotoShare(QWidget *parent)
: MainPage(parent)
{
        ui.setupUi(this);

        mAlbumSelected = NULL;
        mPhotoSelected = NULL;

        connect( ui.toolButton_NewAlbum, SIGNAL(clicked()), this, SLOT(createAlbum()));
        connect( ui.toolButton_ViewAlbum, SIGNAL(clicked()), this, SLOT(OpenAlbumDialog()));
        connect( ui.toolButton_SlideShow, SIGNAL(clicked()), this, SLOT(OpenSlideShow()));
        connect( ui.toolButton_subscribe, SIGNAL(clicked()), this, SLOT(subscribeToAlbum()));
        connect(ui.toolButton_ViewPhoto, SIGNAL(clicked()), this, SLOT(OpenPhotoDialog()));

        connect( ui.pushButton_YourAlbums, SIGNAL(clicked()), this, SLOT(updateAlbums()));
        connect( ui.pushButton_SharedAlbums, SIGNAL(clicked()), this, SLOT(updateAlbums()));
        connect( ui.pushButton_SubscribedAlbums, SIGNAL(clicked()), this, SLOT(updateAlbums()));

        ui.pushButton_YourAlbums->setChecked(true); // default to your albums view

        QTimer *timer = new QTimer(this);
        timer->connect(timer, SIGNAL(timeout()), this, SLOT(checkUpdate()));
        timer->start(1000);

        /* setup TokenQueue */
        mPhotoQueue = new TokenQueue(rsPhoto->getTokenService(), this);
        requestAlbumData();
}

void PhotoShare::notifySelection(PhotoShareItem *selection)
{

    AlbumItem* aItem;
    PhotoItem* pItem;

    if((aItem = dynamic_cast<AlbumItem*>(selection)) != NULL)
    {

        if(mPhotoSelected)
            mPhotoSelected->setSelected(false);

        if(mAlbumSelected == aItem)
        {
            mAlbumSelected->setSelected(true);
        }
        else
        {
            if(mAlbumSelected  == NULL)
            {
                mAlbumSelected = aItem;
            }
            else
            {
                mAlbumSelected->setSelected(false);
                mAlbumSelected = aItem;
            }

            mAlbumSelected->setSelected(true);

            // get photo data
            std::list<RsGxsGroupId> grpIds;
            grpIds.push_back(mAlbumSelected->getAlbum().mMeta.mGroupId);
            requestPhotoData(grpIds);
        }
    }
    else if((pItem = dynamic_cast<PhotoItem*>(selection)) != NULL)
    {
        if(mPhotoSelected == pItem)
        {
            mPhotoSelected->setSelected(true);
        }
        else
        {
            if(mPhotoSelected  == NULL)
            {
                mPhotoSelected = pItem;
            }
            else
            {
                mPhotoSelected->setSelected(false);
                mPhotoSelected = pItem;
            }

            mPhotoSelected->setSelected(true);
        }
    }
    else
    {

    }

}


void PhotoShare::checkUpdate()
{
        /* update */
        if (!rsPhoto)
                return;

        if (rsPhoto->updated())
        {
                //insertAlbums();
            std::list<std::string> grpIds;
            rsPhoto->groupsChanged(grpIds);
            if(!grpIds.empty())
            {
                RsTokReqOptions opts;
                uint32_t token;
                opts.mReqType = GXS_REQUEST_TYPE_GROUP_DATA;
                mPhotoQueue->requestGroupInfo(token, RS_TOKREQ_ANSTYPE_DATA, opts, grpIds, 0);
            }

            GxsMsgIdResult res;
            rsPhoto->msgsChanged(res);
            if(!res.empty())
                requestPhotoList(res);
        }

        return;
}


/*************** New Photo Dialog ***************/

void PhotoShare::OpenSlideShow()
{
    // TODO.
    if (!mAlbumSelected) {
        // ALERT.
        int ret = QMessageBox::information(this, tr("PhotoShare"),
                                           tr("Please select an album before\n"
                                              "requesting to edit it!"),
                                           QMessageBox::Ok);
        return;
    }

    PhotoSlideShow *dlg = new PhotoSlideShow(mAlbumSelected->getAlbum(), NULL);
    dlg->show();
}


/*************** New Photo Dialog ***************/

void PhotoShare::createAlbum()
{
    AlbumCreateDialog albumCreate(mPhotoQueue, rsPhoto, this);
    albumCreate.exec();
}

void PhotoShare::OpenAlbumDialog()
{
    if (mAlbumSelected) {
        AlbumDialog dlg(mAlbumSelected->getAlbum(), mPhotoQueue, rsPhoto);
        dlg.exec();
    }
}

void PhotoShare::OpenPhotoDialog()
{
    if (mPhotoSelected) {
        PhotoDialog *dlg = new PhotoDialog(rsPhoto, mPhotoSelected->getPhotoDetails());
        dlg->show();
    }
}

/*************** Edit Photo Dialog ***************/

void PhotoShare::clearAlbums()
{
    clearPhotos();

    std::cerr << "PhotoShare::clearAlbums()" << std::endl;
    QLayout *alayout = ui.scrollAreaWidgetContents->layout();

    QSetIterator<AlbumItem*> sit(mAlbumItems);

    while(sit.hasNext())
    {
        AlbumItem* item = sit.next();
        alayout->removeWidget(item);
        item->setParent(NULL);
    }

    // set no albums to be selected
    if(mAlbumSelected)
    {
        mAlbumSelected->setSelected(false);
        mAlbumSelected = NULL;
    }
}

void PhotoShare::deleteAlbums()
{
    std::cerr << "PhotoShare::clearAlbums()" << std::endl;
    QLayout *alayout = ui.scrollAreaWidgetContents->layout();

    QSetIterator<AlbumItem*> sit(mAlbumItems);

    while(sit.hasNext())
    {
        AlbumItem* item = sit.next();
        alayout->removeWidget(item);
        delete item;
    }

    mAlbumItems.clear();

    mAlbumSelected = NULL;
}


void PhotoShare::clearPhotos()
{
    std::cerr << "PhotoShare::clearPhotos()" << std::endl;

    QLayout *layout = ui.scrollAreaWidgetContents_2->layout();

    if(mAlbumSelected)
    {
        QSetIterator<PhotoItem*> sit(mPhotoItems);

        while(sit.hasNext())
        {
            PhotoItem* item  = sit.next();
            layout->removeWidget(item);
            item->setParent(NULL);
            delete item; // remove item
        }
        mPhotoItems.clear();
    }
    mPhotoSelected = NULL;
}

void PhotoShare::updateAlbums()
{

    clearAlbums();

    QLayout *alayout = ui.scrollAreaWidgetContents->layout();
    QSetIterator<AlbumItem*> sit(mAlbumItems);

    if(ui.pushButton_YourAlbums->isChecked())
    {

        ui.toolButton_subscribe->setEnabled(false);
        ui.toolButton_NewAlbum->setEnabled(true);
        ui.toolButton_SlideShow->setEnabled(true);

        while(sit.hasNext()){

            AlbumItem* item = sit.next();
            uint32_t flags = item->getAlbum().mMeta.mSubscribeFlags;

            if(IS_ALBUM_ADMIN(flags))
                alayout->addWidget(item);
        }
    }else if(ui.pushButton_SubscribedAlbums->isChecked())
    {

        ui.toolButton_subscribe->setEnabled(true);
        ui.toolButton_subscribe->setText("Unsubscribe From Album");
        ui.toolButton_subscribe->setIcon(QIcon(":/images/album_unsubscribe.png"));
        //ui.toolButton_NewAlbum->setEnabled(false);
        ui.toolButton_SlideShow->setEnabled(true);

        while(sit.hasNext()){

            AlbumItem* item = sit.next();
            uint32_t flags = item->getAlbum().mMeta.mSubscribeFlags;

            if(IS_ALBUM_SUBSCRIBED(flags))
                alayout->addWidget(item);
        }

    }else if(ui.pushButton_SharedAlbums->isChecked())
    {

        ui.toolButton_subscribe->setEnabled(true);
        ui.toolButton_subscribe->setText("Subscribe To Album");
        ui.toolButton_subscribe->setIcon(QIcon(":/images/album_subscribe.png"));
        //ui.toolButton_NewAlbum->setEnabled(false);
        ui.toolButton_SlideShow->setEnabled(false);

        while(sit.hasNext()){

            AlbumItem* item = sit.next();
            uint32_t flags = item->getAlbum().mMeta.mSubscribeFlags;

            if(IS_ALBUM_N_SUBSCR_OR_ADMIN(flags))
                alayout->addWidget(item);

        }
    }
}

void PhotoShare::deleteAlbum(const RsGxsGroupId &grpId)
{

    QSetIterator<AlbumItem*> sit(mAlbumItems);

    while(sit.hasNext())
    {
        AlbumItem* item = sit.next();

        if(item->getAlbum().mMeta.mGroupId == grpId){

            if(mAlbumSelected == item)
            {
                item->setSelected(false);
                mAlbumSelected = NULL;
            }

            QLayout *alayout = ui.scrollAreaWidgetContents->layout();
            alayout->removeWidget(item);
            mAlbumItems.remove(item);
            item->setParent(NULL);
            delete item;
            return;
        }
    }
}

void PhotoShare::addAlbum(const RsPhotoAlbum &album)
{
    std::cerr << " PhotoShare::addAlbum() AlbumId: " << album.mMeta.mGroupId << std::endl;

    deleteAlbum(album.mMeta.mGroupId); // remove from ui
    AlbumItem *item = new AlbumItem(album, this, this);
    mAlbumItems.insert(item);
}


void PhotoShare::addPhoto(const RsPhotoPhoto &photo)
{
    std::cerr << "PhotoShare::addPhoto() AlbumId: " << photo.mMeta.mGroupId;
    std::cerr << " PhotoId: " << photo.mMeta.mMsgId;
    std::cerr << std::endl;

    PhotoItem* item = new PhotoItem(this, photo, this);
    mPhotoItems.insert(item);
}

void PhotoShare::subscribeToAlbum()
{
    if(mAlbumSelected){
        RsGxsGroupId id = mAlbumSelected->getAlbum().mMeta.mGroupId;
        uint32_t token;

        if(IS_ALBUM_SUBSCRIBED(mAlbumSelected->getAlbum().mMeta.mSubscribeFlags))
            rsPhoto->subscribeToAlbum(token, id, false);
        else if(IS_ALBUM_ADMIN(mAlbumSelected->getAlbum().mMeta.mSubscribeFlags))
            return;
        else if(IS_ALBUM_N_SUBSCR_OR_ADMIN(
                mAlbumSelected->getAlbum().mMeta.mSubscribeFlags))
            rsPhoto->subscribeToAlbum(token, id, true);
        else
            return;

        mPhotoQueue->queueRequest(token, TOKENREQ_GROUPINFO, RS_TOKREQ_ANSTYPE_ACK, 0);
    }
}

void PhotoShare::updatePhotos()
{

    if(mAlbumSelected)
    {
        QSetIterator<PhotoItem*> sit(mPhotoItems);

        while(sit.hasNext())
        {
            QLayout *layout = ui.scrollAreaWidgetContents_2->layout();
            layout->addWidget(sit.next());
        }
    }
}

/**************************** Request / Response Filling of Data ************************/


void PhotoShare::requestAlbumList(std::list<std::string>& ids)
{
        RsTokReqOptions opts;
        opts.mReqType = GXS_REQUEST_TYPE_GROUP_IDS;
        uint32_t token;
        mPhotoQueue->requestGroupInfo(token, RS_TOKREQ_ANSTYPE_LIST, opts, ids, 0);
}

void PhotoShare::requestPhotoList(GxsMsgReq& req)
{
    RsTokReqOptions opts;
    opts.mReqType = GXS_REQUEST_TYPE_MSG_IDS;
    uint32_t token;
    mPhotoQueue->requestMsgInfo(token, RS_TOKREQ_ANSTYPE_LIST, opts, req, 0);
    return;
}


void PhotoShare::loadAlbumList(const uint32_t &token)
{
        std::cerr << "PhotoShare::loadAlbumList()";
        std::cerr << std::endl;

        std::list<std::string> albumIds;
        rsPhoto->getGroupList(token, albumIds);

        requestAlbumData(albumIds);

        std::list<std::string>::iterator it;
        for(it = albumIds.begin(); it != albumIds.end(); it++)
        {
                requestPhotoList(*it);
        }
}


void PhotoShare::requestAlbumData(std::list<RsGxsGroupId> &ids)
{
        RsTokReqOptions opts;
        uint32_t token;
        opts.mReqType = GXS_REQUEST_TYPE_GROUP_DATA;
        mPhotoQueue->requestGroupInfo(token, RS_TOKREQ_ANSTYPE_DATA, opts, ids, 0);
}

void PhotoShare::requestAlbumData()
{
        RsTokReqOptions opts;
        uint32_t token;
        opts.mReqType = GXS_REQUEST_TYPE_GROUP_DATA;
        mPhotoQueue->requestGroupInfo(token, RS_TOKREQ_ANSTYPE_DATA, opts, 0);
}

bool PhotoShare::loadAlbumData(const uint32_t &token)
{
    std::cerr << "PhotoShare::loadAlbumData()";
    std::cerr << std::endl;

    std::vector<RsPhotoAlbum> albums;
    rsPhoto->getAlbum(token, albums);

    std::vector<RsPhotoAlbum>::iterator vit = albums.begin();

    for(; vit != albums.end(); vit++)
    {
        RsPhotoAlbum& album = *vit;

        std::cerr << " PhotoShare::addAlbum() AlbumId: " << album.mMeta.mGroupId << std::endl;

        addAlbum(album);
    }

    updateAlbums();
    return true;
}


void PhotoShare::requestPhotoList(const std::string &albumId)
{

    std::list<RsGxsGroupId> grpIds;
    grpIds.push_back(albumId);
    RsTokReqOptions opts;
    opts.mReqType = GXS_REQUEST_TYPE_MSG_IDS;
    opts.mOptions = RS_TOKREQOPT_MSG_LATEST;
    uint32_t token;
    mPhotoQueue->requestMsgInfo(token, RS_TOKREQ_ANSTYPE_LIST, opts, grpIds, 0);
}


void PhotoShare::acknowledgeGroup(const uint32_t &token)
{
    RsGxsGroupId grpId;
    rsPhoto->acknowledgeGrp(token, grpId);

    if(!grpId.empty())
    {
        std::list<RsGxsGroupId> grpIds;
        grpIds.push_back(grpId);

        RsTokReqOptions opts;
        opts.mReqType = GXS_REQUEST_TYPE_GROUP_DATA;
        uint32_t reqToken;
        mPhotoQueue->requestGroupInfo(reqToken, RS_TOKREQ_ANSTYPE_DATA, opts, grpIds, 0);
    }
}

void PhotoShare::acknowledgeMessage(const uint32_t &token)
{
    std::pair<RsGxsGroupId, RsGxsMessageId> p;
    rsPhoto->acknowledgeMsg(token, p);

    // just acknowledge don't load it
    // loading is only instigated by clicking an album (i.e. requesting photo data)
    // but load it if the album is selected
//    if(!p.first.empty())
//    {
//        if(mAlbumSelected)
//        {
//            if(mAlbumSelected->getAlbum().mMeta.mGroupId == p.first)
//            {
//                std::list<RsGxsGroupId> grpIds;
//                grpIds.push_back(p.first);
//                requestPhotoData(grpIds);
//            }
//        }
//    }
}

void PhotoShare::loadPhotoList(const uint32_t &token)
{
        std::cerr << "PhotoShare::loadPhotoList()";
        std::cerr << std::endl;

        GxsMsgIdResult res;

        rsPhoto->getMsgList(token, res);
        requestPhotoData(res);
}


void PhotoShare::requestPhotoData(GxsMsgReq &photoIds)
{
        RsTokReqOptions opts;
        opts.mReqType = GXS_REQUEST_TYPE_MSG_DATA;
        uint32_t token;
        mPhotoQueue->requestMsgInfo(token, RS_TOKREQ_ANSTYPE_DATA, opts, photoIds, 0);
}

void PhotoShare::requestPhotoData(const std::list<RsGxsGroupId>& grpIds)
{
        RsTokReqOptions opts;
        opts.mReqType = GXS_REQUEST_TYPE_MSG_DATA;
        uint32_t token;
        mPhotoQueue->requestMsgInfo(token, RS_TOKREQ_ANSTYPE_DATA, opts, grpIds, 0);
}


void PhotoShare::loadPhotoData(const uint32_t &token)
{
        std::cerr << "PhotoShare::loadPhotoData()";
        std::cerr << std::endl;

        clearPhotos();

        PhotoResult res;
        rsPhoto->getPhoto(token, res);
        PhotoResult::iterator mit = res.begin();


        for(; mit != res.end(); mit++)
        {
            std::vector<RsPhotoPhoto>& photoV = mit->second;
            std::vector<RsPhotoPhoto>::iterator vit = photoV.begin();

            for(; vit != photoV.end(); vit++)
            {
                RsPhotoPhoto& photo = *vit;
                addPhoto(photo);
                std::cerr << "PhotoShare::loadPhotoData() AlbumId: " << photo.mMeta.mGroupId;
                std::cerr << " PhotoId: " << photo.mMeta.mMsgId;
                std::cerr << std::endl;
            }
        }
        updatePhotos();
}


/**************************** Request / Response Filling of Data ************************/

void PhotoShare::loadRequest(const TokenQueue *queue, const TokenRequest &req)
{
        std::cerr << "PhotoShare::loadRequest()";
        std::cerr << std::endl;

        if (queue == mPhotoQueue)
        {
                /* now switch on req */
                switch(req.mType)
                {
                        case TOKENREQ_GROUPINFO:
                                switch(req.mAnsType)
                                {
                                        case RS_TOKREQ_ANSTYPE_LIST:
                                                loadAlbumList(req.mToken);
                                                break;
                                        case RS_TOKREQ_ANSTYPE_DATA:
                                                loadAlbumData(req.mToken);
                                                break;
                                        case RS_TOKREQ_ANSTYPE_ACK:
                                                acknowledgeGroup(req.mToken);
                                                break;
                                        default:
                                                std::cerr << "PhotoShare::loadRequest() ERROR: GROUP: INVALID ANS TYPE";
                                                std::cerr << std::endl;
                                                break;
                                }
                                break;
                        case TOKENREQ_MSGINFO:
                                switch(req.mAnsType)
                                {
                                        case RS_TOKREQ_ANSTYPE_LIST:
                                                loadPhotoList(req.mToken);
                                                break;
                                        case RS_TOKREQ_ANSTYPE_ACK:
                                                acknowledgeMessage(req.mToken);
                                                break;
                                        case RS_TOKREQ_ANSTYPE_DATA:
                                                loadPhotoData(req.mToken);
                                                break;
                                        default:
                                                std::cerr << "PhotoShare::loadRequest() ERROR: MSG: INVALID ANS TYPE";
                                                std::cerr << std::endl;
                                                break;
                                }
                                break;
                        case TOKENREQ_MSGRELATEDINFO:
                                switch(req.mAnsType)
                                {
                                        case RS_TOKREQ_ANSTYPE_DATA:
                                                loadPhotoData(req.mToken);
                                                break;
                                        default:
                                                std::cerr << "PhotoShare::loadRequest() ERROR: MSG: INVALID ANS TYPE";
                                                std::cerr << std::endl;
                                                break;
                                }
                                break;
                        default:
                                std::cerr << "PhotoShare::loadRequest() ERROR: INVALID TYPE";
                                std::cerr << std::endl;
                                break;
                }
        }
}


/**************************** Request / Response Filling of Data ************************/

