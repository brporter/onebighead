import { useMemo } from 'react';
import type { CreateItemTemplateRequest, UpdateItemTemplateRequest } from '../../utils/types';
import type { TemplateGateway } from '../contracts';
import type { RequestOptions } from '../../api/transport';

/** Template consumers own their reads; this adapter supplies stable, independent operations. */
export function useTemplates(gateway: TemplateGateway) {
  return useMemo(() => ({
    fetchItemTemplates: (options?: RequestOptions) => gateway.getAll(undefined, options),
    loadCollectionTemplates: (id: number, options?: RequestOptions) => gateway.getForCollection(id, options),
    createItemTemplate: (request: CreateItemTemplateRequest) => gateway.create(request),
    updateItemTemplate: (id: number, request: UpdateItemTemplateRequest) => gateway.update(id, request),
    deleteItemTemplate: (id: number) => gateway.delete(id),
    associateTemplateWithCollection: (collectionId: number, templateId: number) => gateway.associateWithCollection(collectionId, templateId),
    disassociateTemplateFromCollection: (collectionId: number, templateId: number) => gateway.disassociateFromCollection(collectionId, templateId),
  }), [gateway]);
}
