/*
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "aos/sm/layermanager.hpp"
#include "aos/common/tools/fs.hpp"
#include "log.hpp"

namespace aos::sm::layermanager {

/***********************************************************************************************************************
 * Static
 **********************************************************************************************************************/

namespace {

RetWithError<StaticString<cFilePathLen>> FilePathFromURI(const String& uri)
{
    StaticArray<StaticString<cFilePathLen>, 2> parts;

    if (auto err = uri.Split(parts, ':'); !err.IsNone()) {
        return {"", err};
    }

    if (parts.Size() != 2) {
        return {"", ErrorEnum::eInvalidArgument};
    }

    if (parts[0] != "file") {
        return {"", ErrorEnum::eInvalidArgument};
    }

    parts[1].LeftTrim("/");

    return {parts[1], ErrorEnum::eNone};
}

LayerData CreateLayerData(const aos::LayerInfo& layer, const aos::oci::ImageManifest& manifest, const String& path)
{
    LayerData layerData = {};

    layerData.mLayerID     = layer.mLayerID;
    layerData.mLayerDigest = layer.mLayerDigest;
    layerData.mVersion     = layer.mVersion;
    layerData.mPath        = path;
    layerData.mSize        = manifest.mConfig.mSize;
    layerData.mState       = LayerStateEnum::eActive;
    layerData.mTimestamp   = Time::Now();

    return layerData;
}

void AcceptAllocatedSpace(spaceallocator::SpaceItf* space)
{
    if (!space) {
        return;
    }

    if (auto err = space->Accept(); !err.IsNone()) {
        LOG_ERR() << "Can't accept space: err=" << err;
    }
}

void ReleaseAllocatedSpace(const String& path, spaceallocator::SpaceItf* space)
{
    if (!path.IsEmpty()) {
        FS::RemoveAll(path);
    }

    if (!space) {
        return;
    }

    if (auto err = space->Release(); !err.IsNone()) {
        LOG_ERR() << "Can't release space: err=" << err;
    }
}

}; // namespace

/***********************************************************************************************************************
 * LayerManager
 **********************************************************************************************************************/

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

Error LayerManager::Init(const Config& config, spaceallocator::SpaceAllocatorItf& layerSpaceAllocator,
    spaceallocator::SpaceAllocatorItf& downloadSpaceAllocator, StorageItf& storage,
    downloader::DownloaderItf& downloader, imagehandler::ImageHandlerItf& imageHandler, oci::OCISpecItf& ociManager)
{
    LOG_DBG() << "Initialize layer manager";

    mConfig = config;

    LOG_DBG() << "Config: layersDir=" << mConfig.mLayersDir << ", downloadDir=" << mConfig.mDownloadDir
              << ", ttl=" << mConfig.mTTL;

    mLayerSpaceAllocator    = &layerSpaceAllocator;
    mDownloadSpaceAllocator = &downloadSpaceAllocator;
    mStorage                = &storage;
    mDownloader             = &downloader;
    mImageHandler           = &imageHandler;
    mOCIManager             = &ociManager;

    if (auto err = FS::ClearDir(mConfig.mDownloadDir); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    if (auto err = FS::MakeDirAll(mConfig.mLayersDir); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    if (auto err = RemoveDamagedLayerFolders(); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    if (auto err = SetOutdatedLayers(); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    if (auto err = RemoveOutdatedLayers(); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    return ErrorEnum::eNone;
}

Error LayerManager::Start()
{
    LOG_DBG() << "Start layer manager";

    const auto interval = mConfig.mTTL / Time::cMilliseconds;

    auto err = mTimer.Create(
        interval,
        [this](void*) {
            if (auto err = RemoveOutdatedLayers(); !err.IsNone()) {
                LOG_ERR() << "Failed to remove outdated layers: err=" << err;
            }
        },
        false);

    if (!err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    return ErrorEnum::eNone;
}

Error LayerManager::Stop()
{
    LOG_DBG() << "Stop layer manager";

    if (auto err = mTimer.Stop(); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    return ErrorEnum::eNone;
}

Error LayerManager::GetLayer(const String& digest, LayerData& layer) const
{
    LOG_DBG() << "Get layer info by digest: digest=" << digest;

    return mStorage->GetLayer(digest, layer);
}

Error LayerManager::ProcessDesiredLayers(const Array<aos::LayerInfo>& desiredLayers)
{
    LockGuard lock {mMutex};

    LOG_DBG() << "Process desired layers";

    auto storageLayers = MakeUnique<LayerDataStaticArray>(&mAllocator);

    if (auto err = mStorage->GetAllLayers(*storageLayers); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    auto layersToInstall = MakeUnique<LayerInfoStaticArray>(&mAllocator, desiredLayers);

    if (auto err = UpdateCachedLayers(*storageLayers, *layersToInstall); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    if (auto err = mInstallPool.Run(); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    for (const auto& layer : *layersToInstall) {
        auto err = mInstallPool.AddTask([this, &layer](void*) {
            if (auto err = InstallLayer(layer); !err.IsNone()) {
                LOG_ERR() << "Failed to install layer: id=" << layer.mLayerID << ", version=" << layer.mVersion
                          << ", digest=" << layer.mLayerDigest << ", err=" << err;
            }
        });
        if (!err.IsNone()) {
            LOG_ERR() << "Failed to add layer install task: id=" << layer.mLayerID << ", version=" << layer.mVersion
                      << ", digest=" << layer.mLayerDigest << ", err=" << err;
        }
    }

    if (auto err = mInstallPool.Wait(); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    LOG_DBG() << "All desired layers installed";

    if (auto err = mInstallPool.Shutdown(); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    return ErrorEnum::eNone;
}

Error LayerManager::RemoveItem(const String& id)
{
    LOG_DBG() << "Remove item: id=" << id;

    LayerData layer;

    if (auto err = mStorage->GetLayer(id, layer); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    if (auto err = RemoveLayer(layer); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    return ErrorEnum::eNone;
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

Error LayerManager::RemoveDamagedLayerFolders()
{
    LOG_DBG() << "Remove damaged layer folders";

    auto layers = MakeUnique<LayerDataStaticArray>(&mAllocator);

    if (auto err = mStorage->GetAllLayers(*layers); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    for (const auto& layer : *layers) {
        if (auto [exists, err] = FS::DirExist(layer.mPath); !err.IsNone() || !exists) {
            LOG_WRN() << "Layer folder does not exist: path=" << layer.mPath;

            if (auto removeErr = RemoveLayer(layer); !removeErr.IsNone()) {
                return AOS_ERROR_WRAP(removeErr);
            }
        }
    }

    for (auto layerDirIterator = FS::DirIterator(mConfig.mLayersDir); layerDirIterator.Next();) {
        if (!layerDirIterator->mIsDir) {
            continue;
        }

        const auto algorithmPath = FS::JoinPath(mConfig.mLayersDir, layerDirIterator->mPath);

        for (auto layerAlgorithmDirIterator = FS::DirIterator(algorithmPath); layerAlgorithmDirIterator.Next();) {
            const auto layerPath = FS::JoinPath(algorithmPath, layerAlgorithmDirIterator->mPath);

            const auto [it, err] = layers->FindIf([&layerPath](const auto& layer) { return layer.mPath == layerPath; });
            if (!err.IsNone()) {
                LOG_WRN() << "Layer missing in storage: path=" << layerPath;

                if (auto removeErr = FS::RemoveAll(layerPath); !removeErr.IsNone()) {
                    return AOS_ERROR_WRAP(removeErr);
                }
            }
        }
    }

    return ErrorEnum::eNone;
}

Error LayerManager::SetOutdatedLayers()
{
    LOG_DBG() << "Set outdated layers";

    auto layers = MakeUnique<LayerDataStaticArray>(&mAllocator);

    if (auto err = mStorage->GetAllLayers(*layers); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    for (const auto& layer : *layers) {
        if (layer.mState != LayerStateEnum::eCached) {
            continue;
        }

        if (auto err = mLayerSpaceAllocator->AddOutdatedItem(layer.mLayerDigest, layer.mSize, layer.mTimestamp);
            !err.IsNone()) {
            return AOS_ERROR_WRAP(err);
        }
    }

    return ErrorEnum::eNone;
}

Error LayerManager::SetLayerState(const LayerData& layer, LayerState state)
{
    LOG_DBG() << "Set layer state: id=" << layer.mLayerID << ", version=" << layer.mVersion
              << ", digest=" << layer.mLayerDigest << ", state=" << state;

    LayerData updatedLayer = layer;
    updatedLayer.mState    = state;

    if (auto err = mStorage->UpdateLayer(updatedLayer); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    if (state == LayerStateEnum::eCached) {
        if (auto err = mLayerSpaceAllocator->AddOutdatedItem(layer.mLayerDigest, layer.mSize, layer.mTimestamp);
            !err.IsNone()) {
            return AOS_ERROR_WRAP(err);
        }

        return ErrorEnum::eNone;
    }

    if (auto err = mLayerSpaceAllocator->RestoreOutdatedItem(layer.mLayerDigest); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    return ErrorEnum::eNone;
}

Error LayerManager::RemoveOutdatedLayers()
{
    LOG_DBG() << "Remove outdated layers";

    auto layers = MakeUnique<LayerDataStaticArray>(&mAllocator);

    if (auto err = mStorage->GetAllLayers(*layers); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    for (const auto& layer : *layers) {
        if (layer.mState != LayerStateEnum::eCached) {
            continue;
        }

        auto expiredTime = layer.mTimestamp.Add(mConfig.mTTL);
        if (Time::Now() < expiredTime) {
            continue;
        }

        if (auto err = RemoveLayer(layer); !err.IsNone()) {
            return AOS_ERROR_WRAP(err);
        }

        if (auto err = mLayerSpaceAllocator->RestoreOutdatedItem(layer.mLayerDigest); !err.IsNone()) {
            LOG_WRN() << "Failed to restore outdated item: err=" << err;
        }
    }

    return ErrorEnum::eNone;
}

Error LayerManager::RemoveLayer(const LayerData& layer)
{
    LOG_DBG() << "Remove layer: id=" << layer.mLayerID << ", version=" << layer.mVersion
              << ", digest=" << layer.mLayerDigest << ", path=" << layer.mPath;

    if (auto err = FS::RemoveAll(layer.mPath); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    if (auto err = mStorage->RemoveLayer(layer.mLayerDigest); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    LOG_INF() << "Layer successfully removed: digest=" << layer.mLayerDigest;

    return ErrorEnum::eNone;
}

Error LayerManager::UpdateCachedLayers(const Array<LayerData>& stored, Array<aos::LayerInfo>& result)
{
    LOG_DBG() << "Update cached layers";

    for (const auto& storageLayer : stored) {
        auto [layer, err] = result.FindIf([&storageLayer](const auto& desiredLayer) {
            return storageLayer.mLayerDigest == desiredLayer.mLayerDigest;
        });

        if (err.IsNone()) {
            if (storageLayer.mState == LayerStateEnum::eCached) {
                if (err = SetLayerState(storageLayer, LayerStateEnum::eActive); !err.IsNone()) {
                    return AOS_ERROR_WRAP(err);
                }
            }

            result.Erase(layer);

            continue;
        }

        if (storageLayer.mState != LayerStateEnum::eCached) {
            if (err = SetLayerState(storageLayer, LayerStateEnum::eCached); !err.IsNone()) {
                return AOS_ERROR_WRAP(err);
            }
        }
    }

    return ErrorEnum::eNone;
}

Error LayerManager::InstallLayer(const aos::LayerInfo& layer)
{
    LOG_DBG() << "Install layer: id=" << layer.mLayerID << ", version=" << layer.mVersion
              << ", digest=" << layer.mLayerDigest;

    Error                               err = ErrorEnum::eNone;
    UniquePtr<spaceallocator::SpaceItf> downloadSpace;
    UniquePtr<spaceallocator::SpaceItf> unpackedSpace;
    StaticString<cFilePathLen>          archivePath;
    StaticString<cFilePathLen>          storeLayerPath;

    auto cleanupDownload = DeferRelease(&err, [&](Error*) {
        LOG_DBG() << "Cleanup download space";

        ReleaseAllocatedSpace(archivePath, downloadSpace.Get());
    });

    auto cleanupLayer = DeferRelease(&err, [&](Error* err) {
        if (err->IsNone()) {
            LOG_DBG() << "Accept layer space";

            AcceptAllocatedSpace(unpackedSpace.Get());

            return;
        }

        LOG_DBG() << "Cleanup layer space";

        ReleaseAllocatedSpace(storeLayerPath, unpackedSpace.Get());
    });

    if (auto [path, uriErr] = FilePathFromURI(layer.mURL); uriErr.IsNone()) {
        archivePath = path;

        cleanupDownload.Release();
    } else {
        Tie(downloadSpace, err) = mDownloadSpaceAllocator->AllocateSpace(layer.mSize);
        if (!err.IsNone()) {
            return AOS_ERROR_WRAP(err);
        }

        archivePath = FS::JoinPath(mConfig.mDownloadDir, layer.mLayerDigest);

        if (err = mDownloader->Download(layer.mURL, archivePath, downloader::DownloadContentEnum::eLayer);
            !err.IsNone()) {
            return AOS_ERROR_WRAP(err);
        }
    }

    if (Tie(storeLayerPath, err) = mImageHandler->InstallLayer(archivePath, mConfig.mLayersDir, layer, unpackedSpace);
        !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    auto manifest = MakeUnique<oci::ImageManifest>(&mAllocator);
    if (err = mOCIManager->LoadImageManifest(FS::JoinPath(storeLayerPath, cLayerOCIDescriptor), *manifest);
        !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    const auto layerData = CreateLayerData(layer, *manifest, storeLayerPath);

    if (err = mStorage->AddLayer(layerData); !err.IsNone()) {
        return AOS_ERROR_WRAP(err);
    }

    LOG_INF() << "Layer successfully installed: id=" << layerData.mLayerID << ", version=" << layerData.mVersion
              << ", digest=" << layerData.mLayerDigest << ", path=" << layerData.mPath;

    return ErrorEnum::eNone;
}

} // namespace aos::sm::layermanager