


export default class ApiFeatures {
    constructor(mongooseQuery, queryData) {
        this.mongooseQuery = mongooseQuery;
        this.queryData = queryData;
    }

    paginate() {
        let { page, limit } = this.queryData;

        if (!page || page <= 0) {
            page = 1
        }

        if (!limit || limit <= 0) {
            limit = 50
        }

        page = parseInt(page)
        limit = parseInt(limit)

        const skip = (page - 1) * limit
        this.mongooseQuery.limit(limit).skip(skip)
        return this
    }

    
    filter() {
        const filterQuery = { ...this.queryData }
        const excludeQueryParams = ['page', 'limit', 'sort', 'search', 'fields']
        excludeQueryParams.forEach(key => {
            delete filterQuery[key]
        })

        this.mongooseQuery.find(JSON.parse((JSON.stringify(filterQuery).replace(/(gt|gte|lt|lte|ne|nin|in)/g, match => `$${match}`))))

        return this
    }

    sort() {
        this.mongooseQuery.sort(this.queryData.sort?.replaceAll(',', ' '))
        return this
    }


    search() {
        if (this.queryData.search) {

            this.mongooseQuery.find({
                $or: [
                    { name: { $regex: this.queryData.search, $options: 'i' } },
                    { fullName: { $regex: this.queryData.search, $options: 'i' } },
                    { 'name.en': { $regex: this.queryData.search, $options: 'i' } },
                    { 'name.ar': { $regex: this.queryData.search, $options: 'i' } },
                    { 'slug.en': { $regex: this.queryData.search, $options: 'i' } },
                    { 'slug.ar': { $regex: this.queryData.search, $options: 'i' } },
                    { code: { $regex: this.queryData.search, $options: 'i' } },
                ]
            })
        }

        return this
    }

    select() {
        this.mongooseQuery.select(this.queryData.fields?.replaceAll(',', ' '))
        return this
    }
}

