import { useCollectionsData, useCategoriesData, useItemsData } from '../../contexts/useData';
import { usePublish } from '../../contexts/usePublish';
import { useUser } from '../../contexts/useUser';
import { useToast } from '../../contexts/useToast';
import { publishManagerApi } from '../../api/publishManager';
import { publicationNotice } from '../../data/publishing/publicationRequirements';
import { PublishResolver } from './PublishResolver';

/** Connect the request workflow to HTTP, caches and notifications at the application boundary. */
export function PublishApp() {
  const { loadCollections, currentCollection } = useCollectionsData();
  const { loadCategoriesForCollection } = useCategoriesData();
  const { refreshLoadedItems } = useItemsData();
  const { pendingRequest, clearIntent } = usePublish();
  const { refetch } = useUser();
  const { showToast } = useToast();
  if (!pendingRequest) return null;

  return <PublishResolver key={pendingRequest.requestId} request={pendingRequest} gateway={publishManagerApi}
    dismiss={() => clearIntent(pendingRequest.requestId)}
    refresh={async (response, signal) => {
      const options = { signal, throwOnError: true };
      await Promise.all([
        loadCollections(options),
        currentCollection ? loadCategoriesForCollection(currentCollection.collectionId, options) : Promise.resolve(),
        refreshLoadedItems(options),
        response.workspaceSlugSet ? refetch({ throwOnError: true }) : Promise.resolve(),
      ]);
      signal.throwIfAborted();
    }}
    complete={response => {
      const notice = publicationNotice(pendingRequest.action, response);
      showToast(notice.message, notice.details);
      clearIntent(pendingRequest.requestId);
    }} />;
}
